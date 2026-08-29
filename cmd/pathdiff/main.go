package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"pathdiff/internal/store"
)

const (
	defaultDB      = "./pathdiff.db"
	defaultControl = "/tmp/pathdiff.sock"
	defaultListen  = ":9911"
)

type controlRequest struct {
	Command string    `json:"command"`
	Since   time.Time `json:"since,omitempty"`
	Path    string    `json:"path,omitempty"`
	Start   time.Time `json:"start,omitempty"`
	End     time.Time `json:"end,omitempty"`
}

type controlResponse struct {
	Error  string        `json:"error,omitempty"`
	Status string        `json:"status,omitempty"`
	Inodes []uint64      `json:"inodes,omitempty"`
	Events []store.Event `json:"events,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "daemon":
		daemonCommand(os.Args[2:])
	case "inodes":
		inodesCommand(os.Args[2:])
	case "events":
		eventsCommand(os.Args[2:])
	case "status", "stop":
		controlCommand(os.Args[1], os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  pathdiff daemon [-db DIR] [-listen ADDR] [-control SOCKET]
  pathdiff inodes -since RFC3339 [-control SOCKET]
  pathdiff events -path PREFIX -start RFC3339 -end RFC3339 [-control SOCKET]
  pathdiff status [-control SOCKET]
  pathdiff stop [-control SOCKET]
`)
}

func daemonCommand(args []string) {
	flags := flag.NewFlagSet("daemon", flag.ExitOnError)
	dbPath := flags.String("db", defaultDB, "Pebble database directory")
	listenAddr := flags.String("listen", defaultListen, "FPolicy event listener address")
	controlPath := flags.String("control", defaultControl, "Unix control socket")
	_ = flags.Parse(args)

	if err := runDaemon(*dbPath, *listenAddr, *controlPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon(dbPath, listenAddr, controlPath string) error {
	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	eventListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen for events: %w", err)
	}
	defer eventListener.Close()

	if err := os.MkdirAll(filepath.Dir(controlPath), 0o755); err != nil {
		return fmt.Errorf("create control socket directory: %w", err)
	}
	if err := os.Remove(controlPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	controlListener, err := net.Listen("unix", controlPath)
	if err != nil {
		return fmt.Errorf("listen for control requests: %w", err)
	}
	defer func() {
		_ = controlListener.Close()
		_ = os.Remove(controlPath)
	}()

	fmt.Printf("pathdiff daemon: events=%s control=%s db=%s\n", listenAddr, controlPath, dbPath)
	context, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var connections sync.WaitGroup
	go acceptEvents(context, eventListener, db, &connections)
	go acceptControls(context, controlListener, db, cancel, &connections)
	<-context.Done()
	_ = eventListener.Close()
	_ = controlListener.Close()
	connections.Wait()
	return nil
}

func acceptEvents(context context.Context, listener net.Listener, db *store.DB, connections *sync.WaitGroup) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if context.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "accept event connection:", err)
			continue
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer connection.Close()
			readEvents(connection, db)
		}()
	}
}

func readEvents(connection net.Conn, db *store.DB) {
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var event store.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			fmt.Fprintln(os.Stderr, "decode event:", err)
			continue
		}
		if event.Path == "" {
			fmt.Fprintln(os.Stderr, "reject event: path is required")
			continue
		}
		if err := db.Store(event); err != nil {
			fmt.Fprintln(os.Stderr, "store event:", err)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "read event stream:", err)
	}
}

func acceptControls(context context.Context, listener net.Listener, db *store.DB, stop context.CancelFunc, connections *sync.WaitGroup) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if context.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "accept control connection:", err)
			continue
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer connection.Close()
			handleControl(connection, db, stop)
		}()
	}
}

func handleControl(connection net.Conn, db *store.DB, stop context.CancelFunc) {
	var request controlRequest
	response := controlResponse{}
	if err := json.NewDecoder(io.LimitReader(connection, 1024*1024)).Decode(&request); err != nil {
		response.Error = "invalid request: " + err.Error()
	} else {
		switch request.Command {
		case "status":
			response.Status = "running"
		case "stop":
			response.Status = "stopping"
			stop()
		case "inodes":
			response.Inodes, err = db.InodesSince(request.Since)
		case "events":
			response.Events, err = db.EventsByPath(request.Path, request.Start, request.End)
		default:
			response.Error = "unknown command"
		}
		if err != nil {
			response.Error = err.Error()
		}
	}
	_ = json.NewEncoder(connection).Encode(response)
}

func inodesCommand(args []string) {
	flags := flag.NewFlagSet("inodes", flag.ExitOnError)
	controlPath := flags.String("control", defaultControl, "Unix control socket")
	sinceValue := flags.String("since", "", "inclusive RFC3339 timestamp")
	_ = flags.Parse(args)
	since, err := parseTime("since", *sinceValue)
	if err != nil {
		fatal(err)
	}
	requestControl(*controlPath, controlRequest{Command: "inodes", Since: since})
}

func eventsCommand(args []string) {
	flags := flag.NewFlagSet("events", flag.ExitOnError)
	controlPath := flags.String("control", defaultControl, "Unix control socket")
	path := flags.String("path", "", "path prefix")
	startValue := flags.String("start", "", "inclusive RFC3339 timestamp")
	endValue := flags.String("end", "", "inclusive RFC3339 timestamp")
	_ = flags.Parse(args)
	if *path == "" {
		fatal(errors.New("path is required"))
	}
	start, err := parseTime("start", *startValue)
	if err != nil {
		fatal(err)
	}
	end, err := parseTime("end", *endValue)
	if err != nil {
		fatal(err)
	}
	if end.Before(start) {
		fatal(errors.New("end must not be before start"))
	}
	requestControl(*controlPath, controlRequest{Command: "events", Path: *path, Start: start, End: end})
}

func controlCommand(command string, args []string) {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	controlPath := flags.String("control", defaultControl, "Unix control socket")
	_ = flags.Parse(args)
	requestControl(*controlPath, controlRequest{Command: command})
}

func requestControl(controlPath string, request controlRequest) {
	connection, err := net.Dial("unix", controlPath)
	if err != nil {
		fatal(fmt.Errorf("connect to daemon: %w", err))
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		fatal(err)
	}
	var response controlResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		fatal(err)
	}
	if response.Error != "" {
		fatal(errors.New(response.Error))
	}
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		fatal(err)
	}
}

func parseTime(name, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%s is required", name)
	}
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", name, err)
	}
	return timestamp, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "pathdiff:", err)
	os.Exit(1)
}
