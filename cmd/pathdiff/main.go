package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"pathdiff/internal/store"

	"github.com/spf13/cobra"
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
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "pathdiff", Short: "Store and inspect FPolicy inode path changes", SilenceUsage: true}
	root.AddCommand(newDaemonCommand(), newInodesCommand(), newEventsCommand(), newMonitorCommand(), newControlCommand("status"), newControlCommand("stop"))
	return root
}

func newDaemonCommand() *cobra.Command {
	var dbPath, listenAddr, controlPath string
	command := &cobra.Command{Use: "daemon", Short: "Run the event receiver and query service", RunE: func(*cobra.Command, []string) error {
		return runDaemon(dbPath, listenAddr, controlPath)
	}}
	command.Flags().StringVar(&dbPath, "db", defaultDB, "Pebble database directory")
	command.Flags().StringVar(&listenAddr, "listen", defaultListen, "FPolicy event listener address")
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	return command
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
		case "recent":
			response.Events, err = db.EventsSince(request.Since)
		default:
			response.Error = "unknown command"
		}
		if err != nil {
			response.Error = err.Error()
		}
	}
	_ = json.NewEncoder(connection).Encode(response)
}

func newInodesCommand() *cobra.Command {
	var controlPath, sinceValue string
	command := &cobra.Command{Use: "inodes", Short: "List unique inodes changed since a timestamp", RunE: func(*cobra.Command, []string) error {
		since, err := parseTime("since", sinceValue)
		if err != nil {
			return err
		}
		response, err := callControl(controlPath, controlRequest{Command: "inodes", Since: since})
		if err != nil {
			return err
		}
		return printResponse(response)
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&sinceValue, "since", "", "inclusive RFC3339 timestamp")
	_ = command.MarkFlagRequired("since")
	return command
}

func newEventsCommand() *cobra.Command {
	var controlPath, path, startValue, endValue string
	command := &cobra.Command{Use: "events", Short: "List changes below a path during a time range", RunE: func(*cobra.Command, []string) error {
		start, err := parseTime("start", startValue)
		if err != nil {
			return err
		}
		end, err := parseTime("end", endValue)
		if err != nil {
			return err
		}
		if end.Before(start) {
			return errors.New("end must not be before start")
		}
		response, err := callControl(controlPath, controlRequest{Command: "events", Path: path, Start: start, End: end})
		if err != nil {
			return err
		}
		return printResponse(response)
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&path, "path", "", "path prefix")
	command.Flags().StringVar(&startValue, "start", "", "inclusive RFC3339 timestamp")
	command.Flags().StringVar(&endValue, "end", "", "inclusive RFC3339 timestamp")
	_ = command.MarkFlagRequired("path")
	_ = command.MarkFlagRequired("start")
	_ = command.MarkFlagRequired("end")
	return command
}

func newMonitorCommand() *cobra.Command {
	var controlPath, sinceValue, path string
	var interval time.Duration
	command := &cobra.Command{Use: "monitor", Short: "Print newly observed inode path changes", RunE: func(command *cobra.Command, _ []string) error {
		if interval <= 0 {
			return errors.New("interval must be greater than zero")
		}
		since := time.Now().UTC()
		var err error
		if sinceValue != "" {
			since, err = parseTime("since", sinceValue)
			if err != nil {
				return err
			}
		}
		context, cancel := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		seen := make(map[string]struct{})
		for {
			response, err := callControl(controlPath, controlRequest{Command: "recent", Since: since})
			if err != nil {
				return err
			}
			for _, event := range response.Events {
				if path != "" && !strings.HasPrefix(event.Path, path) {
					continue
				}
				key := fmt.Sprintf("%d:%s:%s:%s", event.Inode, event.Path, event.Operation, event.Timestamp.UTC().Format(time.RFC3339Nano))
				if event.Timestamp.After(since) {
					since = event.Timestamp
					seen = make(map[string]struct{})
				}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				if err := json.NewEncoder(command.OutOrStdout()).Encode(event); err != nil {
					return err
				}
			}
			select {
			case <-context.Done():
				return nil
			case <-ticker.C:
			}
		}
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&sinceValue, "since", "", "RFC3339 timestamp; defaults to now")
	command.Flags().StringVar(&path, "path", "", "optional path prefix")
	command.Flags().DurationVar(&interval, "interval", time.Second, "poll interval")
	return command
}

func newControlCommand(name string) *cobra.Command {
	var controlPath string
	command := &cobra.Command{Use: name, Short: name + " the daemon", RunE: func(*cobra.Command, []string) error {
		response, err := callControl(controlPath, controlRequest{Command: name})
		if err != nil {
			return err
		}
		return printResponse(response)
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	return command
}

func callControl(controlPath string, request controlRequest) (controlResponse, error) {
	connection, err := net.Dial("unix", controlPath)
	if err != nil {
		return controlResponse{}, fmt.Errorf("connect to daemon: %w", err)
	}
	defer connection.Close()
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return controlResponse{}, err
	}
	var response controlResponse
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return controlResponse{}, err
	}
	if response.Error != "" {
		return controlResponse{}, errors.New(response.Error)
	}
	return response, nil
}

func printResponse(response controlResponse) error {
	return json.NewEncoder(os.Stdout).Encode(response)
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
