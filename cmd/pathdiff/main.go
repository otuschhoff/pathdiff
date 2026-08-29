package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"pathdiff/internal/fpolicy"
	"pathdiff/internal/store"

	"github.com/spf13/cobra"
)

const (
	defaultDB      = "pathdiff_data"
	defaultControl = "/tmp/pathdiff.sock"
	defaultListen  = ":9911"
)

var captureSequence atomic.Uint64

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
	var dbPath, listenAddr, controlPath, recordDir string
	command := &cobra.Command{Use: "daemon", Short: "Run the event receiver and query service", RunE: func(*cobra.Command, []string) error {
		return runDaemon(dbPath, listenAddr, controlPath, recordDir)
	}}
	command.Flags().StringVar(&dbPath, "db", defaultDB, "Pebble database directory")
	command.Flags().StringVar(&listenAddr, "listen", defaultListen, "FPolicy event listener address")
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&recordDir, "record-dir", "", "directory for raw per-connection .in and .out captures")
	return command
}

func runDaemon(dbPath, listenAddr, controlPath, recordDir string) error {
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
	go acceptEvents(context, eventListener, db, recordDir, &connections)
	go acceptControls(context, controlListener, db, cancel, &connections)
	<-context.Done()
	_ = eventListener.Close()
	_ = controlListener.Close()
	connections.Wait()
	return nil
}

func acceptEvents(context context.Context, listener net.Listener, db *store.DB, recordDir string, connections *sync.WaitGroup) {
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
			activeConnection := connection
			if recordDir != "" {
				var err error
				activeConnection, err = newTrafficRecorder(connection, recordDir)
				if err != nil {
					fmt.Fprintln(os.Stderr, "create traffic capture:", err)
					_ = connection.Close()
					return
				}
			}
			defer activeConnection.Close()
			readEvents(activeConnection, db)
		}()
	}
}

type trafficRecorder struct {
	net.Conn
	in, out *os.File
}

func newTrafficRecorder(connection net.Conn, directory string) (*trafficRecorder, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("%s-%06d", time.Now().UTC().Format("20060102T150405.000000000Z"), captureSequence.Add(1))
	in, err := os.Create(filepath.Join(directory, prefix+".in"))
	if err != nil {
		return nil, err
	}
	out, err := os.Create(filepath.Join(directory, prefix+".out"))
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	return &trafficRecorder{Conn: connection, in: in, out: out}, nil
}

func (r *trafficRecorder) Read(payload []byte) (int, error) {
	count, err := r.Conn.Read(payload)
	if count > 0 {
		_, _ = r.in.Write(payload[:count])
	}
	return count, err
}

func (r *trafficRecorder) Write(payload []byte) (int, error) {
	count, err := r.Conn.Write(payload)
	if count > 0 {
		_, _ = r.out.Write(payload[:count])
	}
	return count, err
}

func (r *trafficRecorder) Close() error {
	_ = r.in.Close()
	_ = r.out.Close()
	return r.Conn.Close()
}

func readEvents(connection net.Conn, db *store.DB) {
	reader := bufio.NewReader(connection)
	first, err := reader.Peek(1)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr, "read event stream:", err)
		}
		return
	}
	if first[0] == '<' {
		readXMLEvents(reader, connection, db)
		return
	}
	if first[0] == 0x22 {
		readONTAPXMLEvents(reader, connection, db)
		return
	}
	if first[0] != '{' {
		readFramedEvents(reader, connection, db)
		return
	}

	scanner := bufio.NewScanner(reader)
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

func readONTAPXMLEvents(reader *bufio.Reader, connection net.Conn, db *store.DB) {
	message, err := fpolicy.ReadONTAPXMLFrame(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read ONTAP XML handshake from %s: %v\n", connection.RemoteAddr(), err)
		return
	}
	if message.Type != "NEGO_REQ" {
		fmt.Fprintf(os.Stderr, "reject ONTAP XML session from %s: expected NEGO_REQ, got %s\n", connection.RemoteAddr(), message.Type)
		return
	}
	response, err := fpolicy.ONTAPNegotiateResponse(message.Session, message.VserverUUID, message.PolicyName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode ONTAP XML handshake response:", err)
		return
	}
	if err := fpolicy.WriteONTAPXMLFrame(connection, "NEGO_RESP", response); err != nil {
		fmt.Fprintf(os.Stderr, "write ONTAP XML handshake response to %s: %v\n", connection.RemoteAddr(), err)
		return
	}

	for {
		message, err := fpolicy.ReadONTAPXMLFrame(reader)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "read ONTAP XML event from %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		if message.Type != "NOTIFY_REQ" {
			fmt.Fprintf(os.Stderr, "ignore ONTAP XML message from %s: %s\n", connection.RemoteAddr(), message.Type)
			continue
		}
		storeXMLEvent(message.Payload, connection, db)
	}
}

func readFramedEvents(reader *bufio.Reader, connection net.Conn, db *store.DB) {
	handshake, err := fpolicy.ReadFrame(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read framed handshake from %s: %v\n", connection.RemoteAddr(), err)
		return
	}
	if bytes.HasPrefix(bytes.TrimSpace(handshake), []byte("<")) {
		message, err := fpolicy.ParseXMLMessage(handshake)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode XML handshake from %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		if !message.Negotiate {
			fmt.Fprintf(os.Stderr, "reject XML session from %s: expected NegotiateRequest\n", connection.RemoteAddr())
			return
		}
		response, err := fpolicy.NegotiateResponse(message.SessionID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encode XML handshake response:", err)
			return
		}
		if err := fpolicy.WriteFrame(connection, response); err != nil {
			fmt.Fprintf(os.Stderr, "write XML handshake response to %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		readFramedXMLEvents(reader, connection, db)
		return
	}
	if err := fpolicy.WriteFrame(connection, nil); err != nil {
		fmt.Fprintf(os.Stderr, "write protobuf handshake response to %s: %v\n", connection.RemoteAddr(), err)
		return
	}
	readProtobufEvents(reader, connection, db)
}

func readProtobufEvents(reader *bufio.Reader, connection net.Conn, db *store.DB) {
	for {
		payload, err := fpolicy.ReadFrame(reader)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "read protobuf event from %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		event, err := fpolicy.ParseNotification(payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode protobuf event from %s: %v\n", connection.RemoteAddr(), err)
			continue
		}
		if err := db.Store(event); err != nil {
			fmt.Fprintln(os.Stderr, "store protobuf event:", err)
		}
	}
}

func readFramedXMLEvents(reader *bufio.Reader, connection net.Conn, db *store.DB) {
	for {
		payload, err := fpolicy.ReadFrame(reader)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "read framed XML event from %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		storeXMLEvent(payload, connection, db)
	}
}

func readXMLEvents(reader *bufio.Reader, connection net.Conn, db *store.DB) {
	decoder := xml.NewDecoder(reader)
	for {
		event, err := fpolicy.DecodeXMLNotification(decoder)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "read XML event from %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		if err := db.Store(event); err != nil {
			fmt.Fprintln(os.Stderr, "store XML event:", err)
		}
	}
}

func storeXMLEvent(payload []byte, connection net.Conn, db *store.DB) {
	event, err := fpolicy.ParseXMLNotification(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode XML event from %s: %v\n", connection.RemoteAddr(), err)
		return
	}
	if err := db.Store(event); err != nil {
		fmt.Fprintln(os.Stderr, "store XML event:", err)
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
