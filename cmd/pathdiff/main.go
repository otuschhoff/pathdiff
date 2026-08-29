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
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"pathdiff/internal/fpolicy"
	"pathdiff/internal/store"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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
	Error       string        `json:"error,omitempty"`
	Status      string        `json:"status,omitempty"`
	Connections int           `json:"connections,omitempty"`
	EventCount  uint64        `json:"event_count,omitempty"`
	DBPath      string        `json:"db_path,omitempty"`
	DBSize      uint64        `json:"db_size,omitempty"`
	Events      []store.Event `json:"events,omitempty"`
	Engines     []engineInfo  `json:"engines,omitempty"`
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "pathdiff", Short: "Store and inspect FPolicy path changes", SilenceUsage: true}
	root.AddGroup(&cobra.Group{ID: "queries", Title: "Query Commands:"}, &cobra.Group{ID: "management", Title: "Management Commands:"}, &cobra.Group{ID: "service", Title: "Service Commands:"}, &cobra.Group{ID: "other", Title: "Other Commands:"})
	root.AddCommand(newDaemonCommand(), newEventsCommand(), newPathCommand(), newVolumeCommand(), newDBCommand(), newEngineCommand(), newServiceCommand())
	root.SetHelpCommandGroupID("other")
	root.InitDefaultCompletionCmd()
	root.CompletionOptions.HiddenDefaultCmd = false
	if completion, _, err := root.Find([]string{"completion"}); err == nil {
		completion.GroupID = "other"
	}
	for _, command := range root.Commands() {
		switch command.Name() {
		case "events", "path":
			command.GroupID = "queries"
		case "volume", "db", "engine":
			command.GroupID = "management"
		case "service":
			command.GroupID = "service"
		}
	}
	return root
}

func newDaemonCommand() *cobra.Command {
	var dbPath, listenAddr, controlPath, recordDir string
	var verbose bool
	run := &cobra.Command{Use: "run", Hidden: true, RunE: func(*cobra.Command, []string) error {
		return runDaemon(dbPath, listenAddr, controlPath, recordDir, verbose)
	}}
	run.Flags().StringVar(&dbPath, "db", defaultDB, "Pebble database directory")
	run.Flags().StringVar(&listenAddr, "listen", defaultListen, "FPolicy event listener address")
	run.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	run.Flags().StringVar(&recordDir, "record-dir", "", "directory for raw per-connection .in and .out captures")
	run.Flags().BoolVarP(&verbose, "verbose", "v", false, "log sender state changes and 10-second throughput reports")
	daemon := &cobra.Command{Use: "daemon", Hidden: true}
	daemon.AddCommand(run)
	return daemon
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
	go acceptControls(context, controlListener, db, cancel, trackers, activeConnections, &connections)
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
			trackers.connect(sender, connection.LocalAddr())
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
	connectedSince time.Time
	localPort      string
	nodeID         string
	svmID          string
}

type engineInfo struct {
	Since       time.Time `json:"since"`
	TotalEvents uint64    `json:"total_events"`
	AverageRate float64   `json:"average_events_per_second"`
	LIFIPv4     string    `json:"lif_ipv4"`
	LIFHostname string    `json:"lif_hostname,omitempty"`
	NodeID      string    `json:"node_id,omitempty"`
	SVMID       string    `json:"svm_id,omitempty"`
	LocalPort   string    `json:"local_port"`
}

func newSenderTracker(verbose bool) *senderTracker {
	return &senderTracker{verbose: verbose, senders: make(map[string]*senderStats)}
}

func (t *senderTracker) connect(sender string, localAddress net.Addr) {
	t.mu.Lock()
	stats := t.sender(sender)
	if stats.active == 0 {
		stats.connectedSince = time.Now().UTC()
		_, stats.localPort, _ = net.SplitHostPort(localAddress.String())
	}
	stats.active++
	active := stats.active
	t.mu.Unlock()
	t.logf("sender=%s state=connected active_connections=%d", sender, active)
}

func (t *senderTracker) negotiated(sender, nodeID, svmID string) {
	t.mu.Lock()
	stats := t.sender(sender)
	stats.nodeID = nodeID
	stats.svmID = svmID
	t.mu.Unlock()
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

func (t *senderTracker) connectionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, stats := range t.senders {
		count += stats.active
	}
	return count
}

func (t *senderTracker) engines() []engineInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	engines := make([]engineInfo, 0, len(t.senders))
	for lifIPv4, stats := range t.senders {
		if stats.active == 0 {
			continue
		}
		elapsed := now.Sub(stats.connectedSince).Seconds()
		average := 0.0
		if elapsed > 0 {
			average = float64(stats.totalEvents) / elapsed
		}
		engines = append(engines, engineInfo{Since: stats.connectedSince, TotalEvents: stats.totalEvents, AverageRate: average, LIFIPv4: lifIPv4, NodeID: stats.nodeID, SVMID: stats.svmID, LocalPort: stats.localPort})
	}
	return engines
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
	trackers.negotiated(sender, message.NodeID, message.VserverUUID)
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

func acceptControls(context context.Context, listener net.Listener, db *store.DB, stop context.CancelFunc, trackers *senderTracker, activeConnections *connectionRegistry, connections *sync.WaitGroup) {
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
			handleControl(connection, db, stop, trackers)
		}()
	}
}

func handleControl(connection net.Conn, db *store.DB, stop context.CancelFunc, trackers *senderTracker) {
	var request controlRequest
	response := controlResponse{}
	if err := json.NewDecoder(io.LimitReader(connection, 1024*1024)).Decode(&request); err != nil {
		response.Error = "invalid request: " + err.Error()
	} else {
		switch request.Command {
		case "status":
			response.Status = "running"
			response.Connections = trackers.connectionCount()
			response.EventCount, err = db.EventCount()
		case "engines":
			response.Engines = trackers.engines()
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
		case "events-reset":
			err = db.ResetEvents()
			if err == nil {
				response.Status = "reset"
			}
		case "db-status":
			var stats store.Stats
			stats, err = db.Stats()
			response.DBPath = stats.Path
			response.DBSize = stats.Size
		default:
			response.Error = "unknown command"
		}
		if err != nil {
			response.Error = err.Error()
		}
	}
	_ = json.NewEncoder(connection).Encode(response)
}

func newDBCommand() *cobra.Command {
	database := &cobra.Command{Use: "db", Short: "Manage persisted data"}
	var statusControlPath string
	status := &cobra.Command{Use: "status", Short: "Show Pebble database status", RunE: func(command *cobra.Command, _ []string) error {
		response, err := callControl(statusControlPath, controlRequest{Command: "db-status"})
		if err != nil {
			return err
		}
		return printDBStatus(command.OutOrStdout(), response)
	}}
	status.Flags().StringVar(&statusControlPath, "control", defaultControl, "Unix control socket")
	event := &cobra.Command{Use: "event", Short: "Manage stored events"}
	var controlPath string
	reset := &cobra.Command{Use: "reset", Short: "Remove all stored event records", RunE: func(*cobra.Command, []string) error {
		response, err := callControl(controlPath, controlRequest{Command: "events-reset"})
		if err != nil {
			return err
		}
		return printResponse(response)
	}}
	reset.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	event.AddCommand(reset)
	database.AddCommand(status)
	database.AddCommand(event)
	return database
}

func newEngineCommand() *cobra.Command {
	engine := &cobra.Command{Use: "engine", Short: "Inspect connected FPolicy engines"}
	var controlPath string
	list := &cobra.Command{Use: "list", Short: "List active FPolicy engines", RunE: func(command *cobra.Command, _ []string) error {
		response, err := callControl(controlPath, controlRequest{Command: "engines"})
		if err != nil {
			return err
		}
		return printEngines(command.OutOrStdout(), response.Engines)
	}}
	list.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	engine.AddCommand(list)
	return engine
}

func printEngines(writer io.Writer, engines []engineInfo) error {
	sort.Slice(engines, func(left, right int) bool { return engines[left].LIFIPv4 < engines[right].LIFIPv4 })
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Since", "Total Events", "Avg Event/s", "LIF IPv4", "LIF Hostname", "Node ID", "SVM ID", "Local Port"})
	for _, engine := range engines {
		engine.LIFHostname = resolveHostname(engine.LIFIPv4)
		tableWriter.AppendRow(table.Row{engine.Since.UTC().Format(time.RFC3339), formatCount(engine.TotalEvents), fmt.Sprintf("%.2f", engine.AverageRate), engine.LIFIPv4, engine.LIFHostname, engine.NodeID, engine.SVMID, engine.LocalPort})
	}
	tableWriter.Render()
	return nil
}

func resolveHostname(address string) string {
	names, err := net.LookupAddr(address)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func printDBStatus(writer io.Writer, response controlResponse) error {
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Path", "Size"})
	tableWriter.AppendRow(table.Row{response.DBPath, formatBytes(response.DBSize)})
	tableWriter.Render()
	return nil
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

func newServiceCommand() *cobra.Command {
	service := &cobra.Command{Use: "service", Short: "Manage the pathdiff systemd service"}
	service.AddCommand(newServiceStartCommand(), newServiceStatusCommand(), newServiceStopCommand(), newServiceMonitorCommand())
	return service
}

func newServiceStartCommand() *cobra.Command {
	var dbPath, listenAddr, controlPath, recordDir string
	var verbose bool
	command := &cobra.Command{Use: "start", Short: "Register and start the user systemd service", RunE: func(command *cobra.Command, _ []string) error {
		unitPath, created, err := ensureSystemdUnit(dbPath, listenAddr, controlPath, recordDir, verbose)
		if err != nil {
			return err
		}
		if created {
			if err := runSystemctlUser("daemon-reload"); err != nil {
				return err
			}
		}
		if err := runSystemctlUser("start", "pathdiff.service"); err != nil {
			return err
		}
		_, err = fmt.Fprintf(command.OutOrStdout(), "pathdiff service started (%s)\n", unitPath)
		return err
	}}
	command.Flags().StringVar(&dbPath, "db", defaultDB, "Pebble database directory")
	command.Flags().StringVar(&listenAddr, "listen", defaultListen, "FPolicy event listener address")
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&recordDir, "record-dir", "", "directory for raw per-connection .in and .out captures")
	command.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable daemon sender diagnostics")
	return command
}

func newServiceStatusCommand() *cobra.Command {
	var controlPath string
	command := &cobra.Command{Use: "status", Short: "Show systemd and daemon status", RunE: func(command *cobra.Command, _ []string) error {
		state, err := systemdServiceState()
		if err != nil {
			return err
		}
		connections, events := "-", "-"
		if state == "active" {
			response, err := callControl(controlPath, controlRequest{Command: "status"})
			if err == nil {
				connections = formatCount(uint64(response.Connections))
				events = formatCount(response.EventCount)
			} else {
				state += " (control unavailable)"
			}
		}
		tableWriter := newTableWriter(command.OutOrStdout())
		tableWriter.AppendHeader(table.Row{"Service", "State", "FPolicy Connections", "Registered Events"})
		tableWriter.AppendRow(table.Row{"pathdiff", state, connections, events})
		tableWriter.Render()
		return nil
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	return command
}

func newServiceStopCommand() *cobra.Command {
	return &cobra.Command{Use: "stop", Short: "Stop the user systemd service", RunE: func(*cobra.Command, []string) error {
		return runSystemctlUser("stop", "pathdiff.service")
	}}
}

func newServiceMonitorCommand() *cobra.Command {
	command := newMonitorCommand()
	command.Use = "monitor"
	command.Short = "Monitor newly observed path changes"
	return command
}

func ensureSystemdUnit(dbPath, listenAddr, controlPath, recordDir string, verbose bool) (string, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, err
	}
	unitPath := filepath.Join(home, ".config", "systemd", "user", "pathdiff.service")
	if _, err := os.Stat(unitPath); err == nil {
		return unitPath, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	executable, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	arguments := []string{shellQuote(executable), "daemon", "run", "--db", shellQuote(dbPath), "--listen", shellQuote(listenAddr), "--control", shellQuote(controlPath)}
	if recordDir != "" {
		arguments = append(arguments, "--record-dir", shellQuote(recordDir))
	}
	if verbose {
		arguments = append(arguments, "--verbose")
	}
	unit := systemdUnit(arguments)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return "", false, err
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return "", false, err
	}
	return unitPath, true, nil
}

func runSystemctlUser(arguments ...string) error {
	output, err := exec.Command("systemctl", append([]string{"--user"}, arguments...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func systemdServiceState() (string, error) {
	output, err := exec.Command("systemctl", "--user", "is-active", "pathdiff.service").Output()
	state := strings.TrimSpace(string(output))
	if state != "" {
		return state, nil
	}
	if exitError, ok := err.(*exec.ExitError); ok && (exitError.ExitCode() == 3 || exitError.ExitCode() == 4) {
		return "not registered", nil
	}
	if err != nil {
		return "", fmt.Errorf("systemctl --user is-active pathdiff.service: %w", err)
	}
	return "unknown", nil
}

func systemdUnit(arguments []string) string {
	return "[Unit]\nDescription=pathdiff FPolicy event receiver\n\n[Service]\nExecStart=" + strings.Join(arguments, " ") + "\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n"
}

func shellQuote(value string) string {
	return strconv.Quote(value)
}

func formatCount(value uint64) string {
	text := strconv.FormatUint(value, 10)
	for index := len(text) - 3; index > 0; index -= 3 {
		text = text[:index] + "," + text[index:]
	}
	return text
}

func formatBytes(value uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	amount := float64(value)
	unit := 0
	for amount >= 1024 && unit < len(units)-1 {
		amount /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", value, units[unit])
	}
	return fmt.Sprintf("%.1f %s", amount, units[unit])
}

func newEventsCommand() *cobra.Command {
	var controlPath, pathPrefix, startValue, endValue string
	var maxResults int
	command := &cobra.Command{Use: "events [path-search]", Args: cobra.MaximumNArgs(1), Short: "List changes below a path during a time range", RunE: func(command *cobra.Command, arguments []string) error {
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
		response, err := callControl(controlPath, controlRequest{Command: "events", Path: pathPrefix, Start: start, End: end})
		if err != nil {
			return err
		}
		wildcard := "*"
		if len(arguments) == 1 {
			wildcard = normalizePathSearch(arguments[0])
		}
		return printEvents(command.OutOrStdout(), response.Events, wildcard, maxResults)
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&pathPrefix, "path", "", "path prefix")
	command.Flags().StringVar(&startValue, "start", "", "inclusive time; RFC3339, YYYY-MM-DD, or relative duration (default 24h ago)")
	command.Flags().StringVar(&endValue, "end", "", "inclusive time; RFC3339, YYYY-MM-DD, or relative duration (default now)")
	command.Flags().IntVar(&maxResults, "max", 100, "maximum results to display")
	return command
}

func newPathCommand() *cobra.Command {
	paths := &cobra.Command{Use: "path", Short: "Query changed paths"}
	paths.AddCommand(newPathListCommand(), newPathParentCommand())
	return paths
}

func newPathListCommand() *cobra.Command {
	return newPathQueryCommand("list [path-search]", "List paths changed during a time range", printPaths)
}

func newPathParentCommand() *cobra.Command {
	return newPathQueryCommand("parent [path-search]", "List parent directories changed during a time range", printParentPaths)
}

func newPathQueryCommand(use, summary string, render func(io.Writer, []store.Event, string, int, string) error) *cobra.Command {
	var controlPath, pathPrefix, startValue, endValue, sortBy string
	var maxResults int
	command := &cobra.Command{Use: use, Args: cobra.MaximumNArgs(1), Short: summary, RunE: func(command *cobra.Command, arguments []string) error {
		start, end, err := eventRange(startValue, endValue, time.Now().UTC())
		if err != nil {
			return err
		}
		response, err := callControl(controlPath, controlRequest{Command: "events", Path: pathPrefix, Start: start, End: end})
		if err != nil {
			return err
		}
		search := "*"
		if len(arguments) == 1 {
			search = normalizePathSearch(arguments[0])
		}
		return render(command.OutOrStdout(), response.Events, search, maxResults, sortBy)
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().StringVar(&pathPrefix, "path", "", "path prefix")
	command.Flags().StringVar(&startValue, "start", "", "inclusive time; RFC3339, YYYY-MM-DD, or relative duration (default 24h ago)")
	command.Flags().StringVar(&endValue, "end", "", "inclusive time; RFC3339, YYYY-MM-DD, or relative duration (default now)")
	command.Flags().IntVar(&maxResults, "max", 100, "maximum paths to display")
	command.Flags().StringVar(&sortBy, "sort", "path", "sort by path or timestamp")
	return command
}

func eventRange(startValue, endValue string, now time.Time) (time.Time, time.Time, error) {
	start, err := parseTimeExpression("start", startValue, now, -24*time.Hour)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	end, err := parseTimeExpression("end", endValue, now, 0)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, errors.New("end must not be before start")
	}
	return start, end, nil
}

func printPaths(writer io.Writer, events []store.Event, wildcard string, maxResults int, sortBy string) error {
	return printPathRows(writer, events, wildcard, maxResults, sortBy, "Path", func(event store.Event) string { return event.Path })
}

func printParentPaths(writer io.Writer, events []store.Event, wildcard string, maxResults int, sortBy string) error {
	if maxResults < 1 {
		return errors.New("max must be greater than zero")
	}
	if sortBy != "path" && sortBy != "timestamp" {
		return fmt.Errorf("unsupported sort %q; use path or timestamp", sortBy)
	}
	type parentRow struct {
		event    store.Event
		children map[string]struct{}
	}
	parents := make(map[string]*parentRow)
	for _, event := range events {
		childPath := event.Path
		parent := filepath.Dir(event.Path)
		matched, err := wildcardMatch(wildcard, parent)
		if err != nil {
			return fmt.Errorf("invalid path wildcard %q: %w", wildcard, err)
		}
		if !matched {
			continue
		}
		key := eventVolume(event) + "\x00" + parent
		row := parents[key]
		if row == nil {
			event.Path = parent
			row = &parentRow{event: event, children: make(map[string]struct{})}
			parents[key] = row
		}
		row.children[childPath] = struct{}{}
		if event.Timestamp.After(row.event.Timestamp) {
			event.Path = parent
			row.event = event
		}
	}
	rows := make([]*parentRow, 0, len(parents))
	for _, row := range parents {
		rows = append(rows, row)
	}
	if len(rows) > maxResults {
		_, err := fmt.Fprintf(writer, "%d changed parents match; increase --max and/or tighten the path search, --path prefix, or time range.\n", len(rows))
		return err
	}
	sort.Slice(rows, func(left, right int) bool {
		if sortBy == "timestamp" {
			return rows[left].event.Timestamp.After(rows[right].event.Timestamp)
		}
		leftVolume, rightVolume := eventVolume(rows[left].event), eventVolume(rows[right].event)
		if leftVolume == rightVolume {
			return rows[left].event.Path < rows[right].event.Path
		}
		return leftVolume < rightVolume
	})

	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Last Change", "Volume", "CNT", "Parent"})
	for _, row := range rows {
		tableWriter.AppendRow(table.Row{row.event.Timestamp.UTC().Format(time.RFC3339Nano), eventVolume(row.event), len(row.children), row.event.Path})
	}
	tableWriter.Render()
	return nil
}

func printPathRows(writer io.Writer, events []store.Event, wildcard string, maxResults int, sortBy, column string, pathFor func(store.Event) string) error {
	if maxResults < 1 {
		return errors.New("max must be greater than zero")
	}
	if sortBy != "path" && sortBy != "timestamp" {
		return fmt.Errorf("unsupported sort %q; use path or timestamp", sortBy)
	}
	paths := make(map[string]store.Event)
	for _, event := range events {
		rowPath := pathFor(event)
		matched, err := wildcardMatch(wildcard, rowPath)
		if err != nil {
			return fmt.Errorf("invalid path wildcard %q: %w", wildcard, err)
		}
		if !matched {
			continue
		}
		key := eventVolume(event) + "\x00" + rowPath
		if existing, found := paths[key]; !found || event.Timestamp.After(existing.Timestamp) {
			event.Path = rowPath
			paths[key] = event
		}
	}
	results := make([]store.Event, 0, len(paths))
	for _, event := range paths {
		results = append(results, event)
	}
	if len(results) > maxResults {
		_, err := fmt.Fprintf(writer, "%d changed %ss match; increase --max and/or tighten the path search, --path prefix, or time range.\n", len(results), strings.ToLower(column))
		return err
	}
	sort.Slice(results, func(left, right int) bool {
		if sortBy == "timestamp" {
			return results[left].Timestamp.After(results[right].Timestamp)
		}
		leftVolume, rightVolume := eventVolume(results[left]), eventVolume(results[right])
		if leftVolume == rightVolume {
			return results[left].Path < results[right].Path
		}
		return leftVolume < rightVolume
	})

	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Last Change", "Volume", column})
	for _, event := range results {
		tableWriter.AppendRow(table.Row{event.Timestamp.UTC().Format(time.RFC3339Nano), eventVolume(event), event.Path})
	}
	tableWriter.Render()
	return nil
}

func eventVolume(event store.Event) string {
	if event.VolumeName != "" {
		return event.VolumeName
	}
	return event.VolumeMSID
}

func printEvents(writer io.Writer, events []store.Event, wildcard string, maxResults int) error {
	if maxResults < 1 {
		return errors.New("max must be greater than zero")
	}
	var matches []store.Event
	for _, event := range events {
		matched, err := wildcardMatch(wildcard, event.Path)
		if err != nil {
			return fmt.Errorf("invalid path wildcard %q: %w", wildcard, err)
		}
		if matched {
			matches = append(matches, event)
		}
	}
	if len(matches) > maxResults {
		_, err := fmt.Fprintf(writer, "%d results match; increase --max and/or tighten the path wildcard, --path prefix, or time range.\n", len(matches))
		return err
	}

	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Timestamp", "Operation", "Path", "Volume MSID", "Volume Name"})
	for _, event := range matches {
		tableWriter.AppendRow(table.Row{event.Timestamp.UTC().Format(time.RFC3339Nano), event.Operation, event.Path, event.VolumeMSID, event.VolumeName})
	}
	tableWriter.Render()
	return nil
}

func newTableWriter(writer io.Writer) table.Writer {
	tableWriter := table.NewWriter()
	tableWriter.SetOutputMirror(writer)
	tableWriter.SetStyle(table.StyleRounded)
	tableWriter.Style().Color.Border = text.Colors{text.FgHiBlack}
	tableWriter.Style().Color.Separator = text.Colors{text.FgHiBlack}
	return tableWriter
}

func wildcardMatch(pattern, value string) (bool, error) {
	var expression strings.Builder
	expression.WriteString("(?i)^")
	for _, character := range pattern {
		switch character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteString("$")
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return false, err
	}
	return compiled.MatchString(value), nil
}

func normalizePathSearch(search string) string {
	if strings.ContainsAny(search, "*?") {
		return search
	}
	return "*" + search + "*"
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
		unit := remaining[index : index+1]
		remaining = remaining[index+1:]
		switch unit {
		case "d":
			days += amount
		case "h":
			duration += time.Duration(amount) * time.Hour
		case "m":
			duration += time.Duration(amount) * time.Minute
		case "M":
			months += amount
		default:
			return time.Time{}, fmt.Errorf("parse %s: unsupported unit %q", name, unit)
		}
	}
	return now.AddDate(0, -months, -days).Add(-duration), nil
}
