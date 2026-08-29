package main

import (
	"bufio"
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
	"strconv"
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
	Command    string    `json:"command"`
	Since      time.Time `json:"since,omitempty"`
	Path       string    `json:"path,omitempty"`
	Start      time.Time `json:"start,omitempty"`
	End        time.Time `json:"end,omitempty"`
	VolumeMSID string    `json:"volume_msid,omitempty"`
	VolumeName string    `json:"volume_name,omitempty"`
}

type controlResponse struct {
	Error  string        `json:"error,omitempty"`
	Status string        `json:"status,omitempty"`
	Events []store.Event `json:"events,omitempty"`
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "pathdiff", Short: "Store and inspect FPolicy path changes", SilenceUsage: true}
	root.AddCommand(newDaemonCommand(), newEventsCommand(), newMonitorCommand(), newVolumeCommand(), newControlCommand("status"), newControlCommand("stop"))
	return root
}

func newDaemonCommand() *cobra.Command {
	var dbPath, listenAddr, controlPath, recordDir string
	var verbose bool
	command := &cobra.Command{Use: "daemon", Short: "Run the event receiver and query service", RunE: func(*cobra.Command, []string) error {
		return runDaemon(dbPath, listenAddr, controlPath, recordDir, verbose)
	}}
	command.Flags().StringVar(&dbPath, "db", defaultDB, "Pebble database directory")
	command.Flags().StringVar(&listenAddr, "listen", defaultListen, "FPolicy event listener address")
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&recordDir, "record-dir", "", "directory for raw per-connection .in and .out captures")
	command.Flags().BoolVarP(&verbose, "verbose", "v", false, "log sender state changes and 10-second throughput reports")
	return command
}

func runDaemon(dbPath, listenAddr, controlPath, recordDir string, verbose bool) error {
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
	activeConnections := newConnectionRegistry()
	trackers := newSenderTracker(verbose)
	go trackers.reportEvery(context, 10*time.Second)
	go acceptEvents(context, eventListener, db, recordDir, trackers, activeConnections, &connections)
	go acceptControls(context, controlListener, db, cancel, activeConnections, &connections)
	<-context.Done()
	_ = eventListener.Close()
	_ = controlListener.Close()
	activeConnections.CloseAll()
	connections.Wait()
	return nil
}

func acceptEvents(context context.Context, listener net.Listener, db *store.DB, recordDir string, trackers *senderTracker, activeConnections *connectionRegistry, connections *sync.WaitGroup) {
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
			activeConnections.Add(connection)
			defer activeConnections.Remove(connection)
			sender := senderName(connection.RemoteAddr())
			trackers.connect(sender)
			defer trackers.disconnect(sender)
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
			readEvents(activeConnection, db, trackers, sender)
		}()
	}
}

type connectionRegistry struct {
	mu          sync.Mutex
	connections map[net.Conn]struct{}
}

func newConnectionRegistry() *connectionRegistry {
	return &connectionRegistry{connections: make(map[net.Conn]struct{})}
}

func (r *connectionRegistry) Add(connection net.Conn) {
	r.mu.Lock()
	r.connections[connection] = struct{}{}
	r.mu.Unlock()
}

func (r *connectionRegistry) Remove(connection net.Conn) {
	r.mu.Lock()
	delete(r.connections, connection)
	r.mu.Unlock()
}

func (r *connectionRegistry) CloseAll() {
	r.mu.Lock()
	connections := make([]net.Conn, 0, len(r.connections))
	for connection := range r.connections {
		connections = append(connections, connection)
	}
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

type senderTracker struct {
	verbose bool
	mu      sync.Mutex
	senders map[string]*senderStats
}

type senderStats struct {
	active         int
	protocol       string
	intervalEvents uint64
	totalEvents    uint64
}

func newSenderTracker(verbose bool) *senderTracker {
	return &senderTracker{verbose: verbose, senders: make(map[string]*senderStats)}
}

func (t *senderTracker) connect(sender string) {
	t.mu.Lock()
	stats := t.sender(sender)
	stats.active++
	active := stats.active
	t.mu.Unlock()
	t.logf("sender=%s state=connected active_connections=%d", sender, active)
}

func (t *senderTracker) disconnect(sender string) {
	t.mu.Lock()
	stats := t.sender(sender)
	if stats.active > 0 {
		stats.active--
	}
	active := stats.active
	t.mu.Unlock()
	t.logf("sender=%s state=disconnected active_connections=%d", sender, active)
}

func (t *senderTracker) protocolDetected(sender, protocol string) {
	t.mu.Lock()
	stats := t.sender(sender)
	changed := stats.protocol != protocol
	stats.protocol = protocol
	t.mu.Unlock()
	if changed {
		t.logf("sender=%s state=protocol_detected protocol=%s", sender, protocol)
	}
}

func (t *senderTracker) eventStored(sender string) {
	t.mu.Lock()
	stats := t.sender(sender)
	stats.intervalEvents++
	stats.totalEvents++
	t.mu.Unlock()
}

func (t *senderTracker) reportEvery(context context.Context, interval time.Duration) {
	if !t.verbose {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-context.Done():
			return
		case <-ticker.C:
			t.mu.Lock()
			for sender, stats := range t.senders {
				events := stats.intervalEvents
				stats.intervalEvents = 0
				fmt.Fprintf(os.Stderr, "sender=%s state=throughput protocol=%s active_connections=%d events=%d interval=%s events_per_second=%.2f total_events=%d\n", sender, stats.protocol, stats.active, events, interval, float64(events)/interval.Seconds(), stats.totalEvents)
			}
			t.mu.Unlock()
		}
	}
}

func (t *senderTracker) sender(name string) *senderStats {
	stats := t.senders[name]
	if stats == nil {
		stats = &senderStats{}
		t.senders[name] = stats
	}
	return stats
}

func (t *senderTracker) logf(format string, arguments ...any) {
	if t.verbose {
		fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	}
}

func senderName(address net.Addr) string {
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
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

func readEvents(connection net.Conn, db *store.DB, trackers *senderTracker, sender string) {
	reader := bufio.NewReader(connection)
	first, err := reader.Peek(1)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr, "read event stream:", err)
		}
		return
	}
	if first[0] == '<' {
		trackers.protocolDetected(sender, "raw-xml")
		readXMLEvents(reader, connection, db, trackers, sender)
		return
	}
	if first[0] == 0x22 {
		trackers.protocolDetected(sender, "ontap-xml")
		readONTAPXMLEvents(reader, connection, db, trackers, sender)
		return
	}
	if first[0] != '{' {
		fmt.Fprintf(os.Stderr, "reject event connection from %s: unsupported protocol prefix %#x\n", connection.RemoteAddr(), first[0])
		return
	}
	trackers.protocolDetected(sender, "json-lines")

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
			continue
		}
		trackers.eventStored(sender)
		trackers.logf("sender=%s state=event_stored operation=%s path=%q", sender, event.Operation, event.Path)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "read event stream:", err)
	}
}

func readONTAPXMLEvents(reader *bufio.Reader, connection net.Conn, db *store.DB, trackers *senderTracker, sender string) {
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
	trackers.logf("sender=%s state=negotiated protocol=ontap-xml policy=%s vserver_uuid=%s", sender, message.PolicyName, message.VserverUUID)

	for {
		message, err := fpolicy.ReadONTAPXMLFrame(reader)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "read ONTAP XML event from %s: %v\n", connection.RemoteAddr(), err)
			return
		}
		if message.Type == "KEEP_ALIVE" {
			trackers.logf("sender=%s state=keep_alive", sender)
			continue
		}
		if message.Type == "SCREEN_REQ" {
			storeScreenEvent(message.Payload, connection, db, trackers, sender)
			continue
		}
		if message.Type != "NOTIFY_REQ" {
			trackers.logf("sender=%s state=message_ignored type=%s", sender, message.Type)
			continue
		}
		storeXMLEvent(message.Payload, connection, db, trackers, sender)
	}
}

func storeScreenEvent(payload []byte, connection net.Conn, db *store.DB, trackers *senderTracker, sender string) {
	event, err := fpolicy.ParseScreenRequest(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode ONTAP XML screen request from %s: %v\n", connection.RemoteAddr(), err)
		return
	}
	if err := db.Store(event); err != nil {
		fmt.Fprintln(os.Stderr, "store ONTAP XML screen request:", err)
		return
	}
	trackers.eventStored(sender)
	trackers.logf("sender=%s state=screen_request_stored operation=%s path=%q", sender, event.Operation, event.Path)
}

func readXMLEvents(reader *bufio.Reader, connection net.Conn, db *store.DB, trackers *senderTracker, sender string) {
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
			continue
		}
		trackers.eventStored(sender)
		trackers.logf("sender=%s state=event_stored operation=%s path=%q", sender, event.Operation, event.Path)
	}
}

func storeXMLEvent(payload []byte, connection net.Conn, db *store.DB, trackers *senderTracker, sender string) {
	event, err := fpolicy.ParseXMLNotification(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode XML event from %s: %v\n", connection.RemoteAddr(), err)
		return
	}
	if err := db.Store(event); err != nil {
		fmt.Fprintln(os.Stderr, "store XML event:", err)
		return
	}
	trackers.eventStored(sender)
	trackers.logf("sender=%s state=event_stored operation=%s path=%q", sender, event.Operation, event.Path)
}

func acceptControls(context context.Context, listener net.Listener, db *store.DB, stop context.CancelFunc, activeConnections *connectionRegistry, connections *sync.WaitGroup) {
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
			activeConnections.Add(connection)
			defer activeConnections.Remove(connection)
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
		case "events":
			response.Events, err = db.EventsByPath(request.Path, request.Start, request.End)
		case "recent":
			response.Events, err = db.EventsSince(request.Since)
		case "volume-set":
			err = db.SetVolumeName(request.VolumeMSID, request.VolumeName)
			if err == nil {
				response.Status = "updated"
			}
		default:
			response.Error = "unknown command"
		}
		if err != nil {
			response.Error = err.Error()
		}
	}
	_ = json.NewEncoder(connection).Encode(response)
}

func newVolumeCommand() *cobra.Command {
	volume := &cobra.Command{Use: "volume", Short: "Manage volume MSID mappings"}
	var controlPath, msid, name string
	set := &cobra.Command{Use: "set", Short: "Map a volume MSID to a volume name", RunE: func(*cobra.Command, []string) error {
		response, err := callControl(controlPath, controlRequest{Command: "volume-set", VolumeMSID: msid, VolumeName: name})
		if err != nil {
			return err
		}
		return printResponse(response)
	}}
	set.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	set.Flags().StringVar(&msid, "msid", "", "ONTAP volume MSID")
	set.Flags().StringVar(&name, "name", "", "volume name")
	_ = set.MarkFlagRequired("msid")
	_ = set.MarkFlagRequired("name")
	volume.AddCommand(set)
	return volume
}

func newEventsCommand() *cobra.Command {
	var controlPath, path, startValue, endValue string
	command := &cobra.Command{Use: "events", Short: "List changes below a path during a time range", RunE: func(*cobra.Command, []string) error {
		now := time.Now().UTC()
		start, err := parseTimeExpression("start", startValue, now, -24*time.Hour)
		if err != nil {
			return err
		}
		end, err := parseTimeExpression("end", endValue, now, 0)
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
	command.Flags().StringVar(&startValue, "start", "", "inclusive time; RFC3339, YYYY-MM-DD, or relative duration (default 24h ago)")
	command.Flags().StringVar(&endValue, "end", "", "inclusive time; RFC3339, YYYY-MM-DD, or relative duration (default now)")
	_ = command.MarkFlagRequired("path")
	return command
}

func newMonitorCommand() *cobra.Command {
	var controlPath, sinceValue, path string
	var interval time.Duration
	command := &cobra.Command{Use: "monitor", Short: "Print newly observed path changes", RunE: func(command *cobra.Command, _ []string) error {
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
				key := fmt.Sprintf("%s:%s:%s", event.Path, event.Operation, event.Timestamp.UTC().Format(time.RFC3339Nano))
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

func parseTimeExpression(name, value string, now time.Time, defaultOffset time.Duration) (time.Time, error) {
	if value == "" {
		return now.Add(defaultOffset), nil
	}
	if timestamp, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return timestamp, nil
	}
	if date, err := time.Parse("2006-01-02", value); err == nil {
		return date, nil
	}

	remaining := value
	months, days := 0, 0
	duration := time.Duration(0)
	monthSeen := false
	for remaining != "" {
		index := 0
		for index < len(remaining) && remaining[index] >= '0' && remaining[index] <= '9' {
			index++
		}
		if index == 0 || index == len(remaining) {
			return time.Time{}, fmt.Errorf("parse %s: invalid time expression %q", name, value)
		}
		amount, err := strconv.Atoi(remaining[:index])
		if err != nil {
			return time.Time{}, fmt.Errorf("parse %s: %w", name, err)
		}
		unit := remaining[index]
		remaining = remaining[index+1:]
		switch unit {
		case 'd':
			days += amount
		case 'h':
			duration += time.Duration(amount) * time.Hour
		case 'm':
			if !monthSeen && duration == 0 && days == 0 {
				months += amount
				monthSeen = true
			} else {
				duration += time.Duration(amount) * time.Minute
			}
		default:
			return time.Time{}, fmt.Errorf("parse %s: unsupported unit %q", name, unit)
		}
	}
	return now.AddDate(0, -months, -days).Add(-duration), nil
}
