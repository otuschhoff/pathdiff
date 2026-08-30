package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
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
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	defaultDB                = "pathdiff_data"
	defaultControl           = "/tmp/pathdiff.sock"
	defaultListen            = ":9911-9999"
	fpolicyPolicyShowCommand = "vserver fpolicy policy show"
	fpolicyEngineShowCommand = "vserver fpolicy policy external-engine show -fields primary-servers,secondary-servers,port,ssl-option"
)

var (
	captureSequence    atomic.Uint64
	listenRangePattern = regexp.MustCompile(`^(.*:)([0-9]+)-([0-9]+)$`)
	unitListenPattern  = regexp.MustCompile(`--listen\s+("[^"]*"|\S+)`)
	pingPacketsPattern = regexp.MustCompile(`(?i)(\d+)\s+packets?\s+(?:(?:are|were)\s+)?received`)
	ansiEscapePattern  = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
)

type controlRequest struct {
	Command    string    `json:"command"`
	Since      time.Time `json:"since,omitempty"`
	Path       string    `json:"path,omitempty"`
	Start      time.Time `json:"start,omitempty"`
	End        time.Time `json:"end,omitempty"`
	VolumeMSID string    `json:"volume_msid,omitempty"`
	VolumeName string    `json:"volume_name,omitempty"`
	SVMID      string    `json:"svm_id,omitempty"`
	SVMName    string    `json:"svm_name,omitempty"`
}

type controlResponse struct {
	Error         string          `json:"error,omitempty"`
	Status        string          `json:"status,omitempty"`
	Connections   int             `json:"connections,omitempty"`
	EventCount    uint64          `json:"event_count,omitempty"`
	RequestRate   float64         `json:"request_rate,omitempty"`
	DBPath        string          `json:"db_path,omitempty"`
	DBSize        uint64          `json:"db_size,omitempty"`
	Events        []store.Event   `json:"events,omitempty"`
	Engines       []engineInfo    `json:"engines,omitempty"`
	Mappings      []store.Mapping `json:"mappings,omitempty"`
	ListenerPorts []listenerPort  `json:"listener_ports,omitempty"`
}

type listenerPort struct {
	Port    int      `json:"port"`
	SVMs    []string `json:"svms"`
	Sources []string `json:"sources"`
}

func main() {
	if err := newRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "pathdiff", Short: "Store and inspect FPolicy path changes", SilenceUsage: true}
	root.AddGroup(&cobra.Group{ID: "queries", Title: "Query Commands:"}, &cobra.Group{ID: "management", Title: "Management Commands:"}, &cobra.Group{ID: "service", Title: "Service Commands:"}, &cobra.Group{ID: "other", Title: "Other Commands:"})
	root.AddCommand(newDaemonCommand(), newEventsCommand(), newPathCommand(), newDBCommand(), newEngineCommand(), newCDOTCommand(), newServiceCommand())
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
		case "volume", "svm", "db", "engine", "cdot":
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

	listenerEndpoints, err := parseListenAddresses(listenAddr)
	if err != nil {
		return fmt.Errorf("listen for events: %w", err)
	}
	receiverEndpoints, err := resolveListenerEndpoints(listenerEndpoints)
	if err != nil {
		return err
	}

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

	var accepts, connections sync.WaitGroup
	activeConnections := newConnectionRegistry()
	trackers := newSenderTracker(verbose)
	listenerManager := newFPolicyListenerManager(context, listenerEndpoints, receiverEndpoints, db, recordDir, trackers, activeConnections, &accepts, &connections)
	defer listenerManager.Close()
	go trackers.reportEvery(context, 10*time.Second)
	accepts.Add(1)
	go acceptControls(context, controlListener, db, cancel, trackers, activeConnections, &accepts, &connections, listenerManager.Refresh, listenerManager.Ports)
	go func() {
		if err := listenerManager.Refresh(); err != nil {
			fmt.Fprintln(os.Stderr, "discover FPolicy senders:", err)
		}
	}()
	go listenerManager.RefreshEvery(context, time.Minute)
	<-context.Done()
	listenerManager.Close()
	_ = controlListener.Close()
	accepts.Wait()
	activeConnections.CloseAll()
	connections.Wait()
	return nil
}

func listenEventPorts(specification string) ([]net.Listener, error) {
	addresses, err := parseListenAddresses(specification)
	if err != nil {
		return nil, err
	}
	listeners := make([]net.Listener, 0, len(addresses))
	for _, address := range addresses {
		listener, err := net.ListenTCP("tcp", address)
		if err != nil {
			closeListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

type managedFPolicyListener struct {
	listener net.Listener
	sources  map[string]struct{}
	svms     []string
}

type fpolicyListenerManager struct {
	mu                sync.Mutex
	refreshMu         sync.Mutex
	context           context.Context
	listenEndpoints   map[int]*net.TCPAddr
	receiverEndpoints []*net.TCPAddr
	db                *store.DB
	recordDir         string
	trackers          *senderTracker
	connections       *connectionRegistry
	acceptGroup       *sync.WaitGroup
	waitGroup         *sync.WaitGroup
	listeners         map[int]*managedFPolicyListener
	enabledPolicies   map[string]struct{}
	portSnapshot      atomic.Value
}

func newFPolicyListenerManager(context context.Context, listenEndpoints, receiverEndpoints []*net.TCPAddr, db *store.DB, recordDir string, trackers *senderTracker, connections *connectionRegistry, acceptGroup, waitGroup *sync.WaitGroup) *fpolicyListenerManager {
	endpoints := make(map[int]*net.TCPAddr, len(listenEndpoints))
	for _, endpoint := range listenEndpoints {
		endpoints[endpoint.Port] = endpoint
	}
	manager := &fpolicyListenerManager{context: context, listenEndpoints: endpoints, receiverEndpoints: receiverEndpoints, db: db, recordDir: recordDir, trackers: trackers, connections: connections, acceptGroup: acceptGroup, waitGroup: waitGroup, listeners: make(map[int]*managedFPolicyListener), enabledPolicies: make(map[string]struct{})}
	manager.portSnapshot.Store([]listenerPort{})
	return manager
}

func (m *fpolicyListenerManager) Refresh() error {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	if err := m.context.Err(); err != nil {
		return err
	}
	expected, err := discoverFPolicySenders(m.context, m.receiverEndpoints)
	if err != nil {
		return err
	}
	if err := m.context.Err(); err != nil {
		return err
	}
	expectedPolicies := make(map[string]struct{})
	for _, sender := range expected {
		for _, policy := range sender.Policies {
			expectedPolicies[policy.SVM+"\x00"+policy.Name] = struct{}{}
		}
	}
	m.mu.Lock()
	for key := range m.enabledPolicies {
		if _, expected := expectedPolicies[key]; !expected {
			delete(m.enabledPolicies, key)
		}
	}
	for port, managed := range m.listeners {
		if sender := expected[port]; sender == nil || !sameSources(managed.sources, sender.Sources) {
			_ = managed.listener.Close()
			delete(m.listeners, port)
		}
	}
	for port, sender := range expected {
		if managed := m.listeners[port]; managed != nil {
			managed.svms = fpolicySenderSVMs(sender)
			continue
		}
		endpoint := m.listenEndpoints[port]
		if endpoint == nil {
			continue
		}
		listener, err := net.ListenTCP("tcp", endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen for FPolicy sender on %s: %v\n", endpoint, err)
			continue
		}
		sources := copySources(sender.Sources)
		m.listeners[port] = &managedFPolicyListener{listener: listener, sources: sources, svms: fpolicySenderSVMs(sender)}
		m.acceptGroup.Add(1)
		go acceptEvents(m.context, listener, sources, m.db, m.recordDir, m.trackers, m.connections, m.acceptGroup, m.waitGroup)
	}
	m.snapshotPortsLocked()
	m.mu.Unlock()
	for _, sender := range expected {
		for _, policy := range sender.Policies {
			key := policy.SVM + "\x00" + policy.Name
			m.mu.Lock()
			if _, enabled := m.enabledPolicies[key]; enabled {
				m.mu.Unlock()
				continue
			}
			m.mu.Unlock()
			if err := tryEnableFPolicyPolicy(m.context, m.db, policy); err != nil {
				if errors.Is(err, context.Canceled) {
					return context.Canceled
				}
				var reachability *fpolicyReachabilityError
				if errors.As(err, &reachability) && reachability.Known {
					continue
				}
				fmt.Fprintf(os.Stderr, "FPolicy activation failed for SVM %s policy %s: %v; will retry on the next cDOT refresh\n", policy.SVM, policy.Name, err)
				continue
			}
			m.mu.Lock()
			m.enabledPolicies[key] = struct{}{}
			m.mu.Unlock()
		}
	}
	return nil
}

func (m *fpolicyListenerManager) RefreshEvery(context context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-context.Done():
			return
		case <-ticker.C:
			if err := m.Refresh(); err != nil {
				fmt.Fprintln(os.Stderr, "refresh FPolicy senders:", err)
			}
		}
	}
}

func (m *fpolicyListenerManager) Close() {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for port, listener := range m.listeners {
		_ = listener.listener.Close()
		delete(m.listeners, port)
	}
	m.snapshotPortsLocked()
}

func (m *fpolicyListenerManager) Ports() []listenerPort {
	if snapshot := m.portSnapshot.Load(); snapshot != nil {
		return append([]listenerPort(nil), snapshot.([]listenerPort)...)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshotPortsLocked()
}

func (m *fpolicyListenerManager) snapshotPortsLocked() []listenerPort {
	ports := make([]listenerPort, 0, len(m.listeners))
	for port, listener := range m.listeners {
		sources := make([]string, 0, len(listener.sources))
		for source := range listener.sources {
			sources = append(sources, source)
		}
		sort.Strings(sources)
		ports = append(ports, listenerPort{Port: port, SVMs: append([]string(nil), listener.svms...), Sources: sources})
	}
	sort.Slice(ports, func(left, right int) bool { return ports[left].Port < ports[right].Port })
	m.portSnapshot.Store(ports)
	return ports
}

func fpolicySenderSVMs(sender *expectedFPolicySender) []string {
	seen := make(map[string]struct{})
	for _, policy := range sender.Policies {
		if policy.SVM != "" {
			seen[policy.SVM] = struct{}{}
		}
	}
	svms := make([]string, 0, len(seen))
	for svm := range seen {
		svms = append(svms, svm)
	}
	sort.Slice(svms, func(left, right int) bool { return strings.ToLower(svms[left]) < strings.ToLower(svms[right]) })
	return svms
}

func sameSources(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for source := range left {
		if _, found := right[source]; !found {
			return false
		}
	}
	return true
}

func copySources(sources map[string]struct{}) map[string]struct{} {
	copy := make(map[string]struct{}, len(sources))
	for source := range sources {
		copy[source] = struct{}{}
	}
	return copy
}

func tryEnableFPolicyPolicy(context context.Context, db *store.DB, policy fpolicyPolicy) error {
	host := defaultCDOTCluster()
	keyFile, err := cdotKeyFile("")
	if err != nil {
		return err
	}
	knownHostsFile, err := cdotKnownHostsFile()
	if err != nil {
		return err
	}
	client, err := openCDOTClient(host, "pathdiff", keyFile, knownHostsFile, false)
	if err != nil {
		return err
	}
	defer client.Close()
	return enableFPolicyPolicy(context, db, client, policy, nil)
}

func parseListenAddresses(specification string) ([]*net.TCPAddr, error) {
	var addresses []*net.TCPAddr
	for _, entry := range strings.Split(specification, ",") {
		entry = strings.TrimSpace(entry)
		match := listenRangePattern.FindStringSubmatch(entry)
		if len(match) == 0 {
			address, err := net.ResolveTCPAddr("tcp", entry)
			if err != nil {
				return nil, fmt.Errorf("parse listener %q: %w", entry, err)
			}
			addresses = append(addresses, address)
			continue
		}
		firstPort, _ := strconv.Atoi(match[2])
		lastPort, _ := strconv.Atoi(match[3])
		if firstPort > lastPort || lastPort > 65535 {
			return nil, fmt.Errorf("invalid listener port range %q", entry)
		}
		for port := firstPort; port <= lastPort; port++ {
			address, err := net.ResolveTCPAddr("tcp", match[1]+strconv.Itoa(port))
			if err != nil {
				return nil, fmt.Errorf("parse listener %q: %w", entry, err)
			}
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("at least one listener is required")
	}
	return addresses, nil
}

func resolveListenerEndpoints(listeners []*net.TCPAddr) ([]*net.TCPAddr, error) {
	endpoints := make([]*net.TCPAddr, 0, len(listeners))
	for _, listener := range listeners {
		endpoint := *listener
		if endpoint.IP == nil || endpoint.IP.IsUnspecified() {
			for _, address := range localAddresses() {
				if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
					endpoint.IP = ip
					break
				}
			}
		}
		if endpoint.IP == nil || endpoint.IP.To4() == nil {
			return nil, fmt.Errorf("resolve pathdiff listener IPv4 address from %q", listener)
		}
		endpoints = append(endpoints, &endpoint)
	}
	return endpoints, nil
}

func acceptEvents(context context.Context, listener net.Listener, allowedSources map[string]struct{}, db *store.DB, recordDir string, trackers *senderTracker, activeConnections *connectionRegistry, accepts, connections *sync.WaitGroup) {
	defer accepts.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if context.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Fprintln(os.Stderr, "accept event connection:", err)
			continue
		}
		if _, allowed := allowedSources[senderName(connection.RemoteAddr())]; !allowed {
			fmt.Fprintf(os.Stderr, "reject unexpected FPolicy sender %s on %s\n", connection.RemoteAddr(), connection.LocalAddr())
			_ = connection.Close()
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
	verbose     bool
	startedAt   time.Time
	mu          sync.Mutex
	totalEvents uint64
	senders     map[string]*senderStats
}

type senderStats struct {
	active         int
	protocol       string
	intervalEvents uint64
	totalEvents    uint64
	sessionEvents  uint64
	connectedSince time.Time
	localPort      string
	nodeID         string
	svmID          string
	lastSeen       time.Time
}

type engineInfo struct {
	Since       time.Time `json:"since"`
	TotalEvents uint64    `json:"total_events"`
	AverageRate float64   `json:"average_events_per_second"`
	LIFIPv4     string    `json:"lif_ipv4"`
	LIFHostname string    `json:"lif_hostname,omitempty"`
	NodeID      string    `json:"node_id,omitempty"`
	SVMID       string    `json:"svm_id,omitempty"`
	NodeName    string    `json:"node_name,omitempty"`
	SVMName     string    `json:"svm_name,omitempty"`
	FPolicy     string    `json:"fpolicy_status,omitempty"`
	LocalPort   string    `json:"local_port"`
	LastSeen    time.Time `json:"last_seen"`
}

func newSenderTracker(verbose bool) *senderTracker {
	return &senderTracker{verbose: verbose, startedAt: time.Now().UTC(), senders: make(map[string]*senderStats)}
}

func (t *senderTracker) connect(sender string, localAddress net.Addr) {
	t.mu.Lock()
	stats := t.sender(sender)
	if stats.active == 0 {
		stats.connectedSince = time.Now().UTC()
		stats.intervalEvents = 0
		stats.sessionEvents = 0
		stats.lastSeen = time.Time{}
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
	if active == 0 {
		delete(t.senders, sender)
	}
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
	stats.sessionEvents++
	stats.lastSeen = time.Now().UTC()
	t.totalEvents++
	t.mu.Unlock()
}

func (t *senderTracker) eventMetadata(sender string) (svmID, nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	stats := t.sender(sender)
	return stats.svmID, stats.nodeID
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

func (t *senderTracker) requestRate(now time.Time) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	elapsed := now.Sub(t.startedAt).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(t.totalEvents) / elapsed
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
			average = float64(stats.sessionEvents) / elapsed
		}
		engines = append(engines, engineInfo{Since: stats.connectedSince, TotalEvents: stats.sessionEvents, AverageRate: average, LIFIPv4: lifIPv4, NodeID: stats.nodeID, SVMID: stats.svmID, LocalPort: stats.localPort, LastSeen: stats.lastSeen})
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
	annotateSenderEvent(&event, trackers, sender)
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
	annotateSenderEvent(&event, trackers, sender)
	if err := db.Store(event); err != nil {
		fmt.Fprintln(os.Stderr, "store XML event:", err)
		return
	}
	trackers.eventStored(sender)
	trackers.logf("sender=%s state=event_stored operation=%s path=%q", sender, event.Operation, event.Path)
}

func annotateSenderEvent(event *store.Event, trackers *senderTracker, sender string) {
	event.SVMID, event.NodeID = trackers.eventMetadata(sender)
	event.LIFIPv4 = sender
}

func acceptControls(context context.Context, listener net.Listener, db *store.DB, stop context.CancelFunc, trackers *senderTracker, activeConnections *connectionRegistry, accepts, connections *sync.WaitGroup, refresh func() error, ports func() []listenerPort) {
	defer accepts.Done()
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
			handleControl(connection, db, stop, trackers, refresh, ports)
		}()
	}
}

func handleControl(connection net.Conn, db *store.DB, stop context.CancelFunc, trackers *senderTracker, refresh func() error, ports func() []listenerPort) {
	var request controlRequest
	response := controlResponse{}
	if err := json.NewDecoder(io.LimitReader(connection, 1024*1024)).Decode(&request); err != nil {
		response.Error = "invalid request: " + err.Error()
	} else {
		switch request.Command {
		case "status":
			response.Status = "running"
			response.Connections = trackers.connectionCount()
			response.ListenerPorts = ports()
			response.EventCount, err = db.EventCount()
			response.RequestRate = trackers.requestRate(time.Now().UTC())
		case "engines":
			response.Engines = trackers.engines()
		case "fpolicy-refresh":
			err = refresh()
			if err == nil {
				response.Status = "refreshed"
			}
		case "listener-ports":
			response.ListenerPorts = ports()
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
		case "volume-list":
			response.Mappings, err = db.ListVolumeMappings()
		case "svm-set":
			err = db.SetSVMName(request.SVMID, request.SVMName)
			if err == nil {
				response.Status = "updated"
			}
		case "svm-list":
			response.Mappings, err = db.ListSVMMappings()
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
	var controlPath, keyFile, knownHostsFile, host, user string
	var acceptNewHostKey, debugSSHExec bool
	list := &cobra.Command{Use: "list", Short: "List active FPolicy engines", RunE: func(command *cobra.Command, _ []string) error {
		response, err := callControl(controlPath, controlRequest{Command: "engines"})
		if err != nil {
			return err
		}
		if host != "" {
			keyPath, err := cdotKeyFile(keyFile)
			if err != nil {
				return err
			}
			if knownHostsFile == "" {
				knownHostsFile, err = cdotKnownHostsFile()
				if err != nil {
					return err
				}
			}
			var debugWriter io.Writer
			if debugSSHExec {
				debugWriter = command.ErrOrStderr()
			}
			client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
			if err != nil {
				return err
			}
			defer client.Close()
			if err := enrichEngines(client, response.Engines, debugWriter); err != nil {
				return err
			}
		}
		return printEngines(command.OutOrStdout(), response.Engines)
	}}
	list.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	list.Flags().StringVar(&host, "host", defaultCDOTCluster(), "cDOT cluster hostname or address")
	list.Flags().StringVar(&user, "user", "pathdiff", "SSH user for cDOT connections")
	list.Flags().StringVar(&keyFile, "key", "", "private key path; defaults to the XDG path")
	list.Flags().StringVar(&knownHostsFile, "known-hosts", "", "known_hosts file; defaults to the XDG path")
	list.Flags().BoolVar(&acceptNewHostKey, "accept-new-host-key", false, "trust and save the host key when known_hosts is absent")
	list.Flags().BoolVar(&debugSSHExec, "debug-ssh-exec", false, "print SSH commands and their results to stderr")
	engine.AddCommand(list)
	return engine
}

func enrichEngines(client *ssh.Client, engines []engineInfo, debugWriter io.Writer) error {
	lifOutput, err := runSSHCommand(client, "network interface show -instance", debugWriter)
	if err != nil {
		return fmt.Errorf("query cDOT LIFs: %w", err)
	}
	svmOutput, err := runSSHCommand(client, "vserver show -instance", debugWriter)
	if err != nil {
		return fmt.Errorf("query cDOT SVMs: %w", err)
	}
	lifs := make(map[string]map[string]string)
	for _, record := range parseONTAPInstances(string(lifOutput)) {
		if address := instanceField(record, "Network Address"); address != "" {
			lifs[address] = record
		}
	}
	svms := make(map[string]string)
	for _, record := range parseONTAPInstances(string(svmOutput)) {
		svms[instanceField(record, "Vserver UUID")] = instanceField(record, "Vserver")
	}
	for index := range engines {
		if lif := lifs[engines[index].LIFIPv4]; lif != nil {
			engines[index].NodeName = instanceField(lif, "Current Node")
			if engines[index].SVMID == "" {
				engines[index].SVMID = instanceField(lif, "Vserver UUID")
			}
		}
		engines[index].SVMName = svms[engines[index].SVMID]
		engines[index].FPolicy = "unavailable"
	}
	fpolicyOutput, err := runSSHCommand(client, "vserver fpolicy show-engine -fields vserver,policy-name,server-status", debugWriter)
	if err != nil {
		return nil
	}
	statuses := fpolicyEngineStatesForServers(string(fpolicyOutput), localAddresses())
	for index := range engines {
		if status := statuses[engines[index].SVMName+"\x00"+engines[index].NodeName]; status != "" {
			engines[index].FPolicy = status
		}
	}
	return nil
}

func fpolicyEngineStatesForServers(output string, servers []string) map[string]string {
	allowed := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		allowed[server] = struct{}{}
	}
	states := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] == "node" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		if _, found := allowed[fields[3]]; !found {
			continue
		}
		key := fields[1] + "\x00" + fields[0]
		if strings.EqualFold(fields[4], "connected") {
			states[key] = "connected"
		} else if states[key] == "" {
			states[key] = "off"
		}
	}
	return states
}

func newCDOTCommand() *cobra.Command {
	cdot := &cobra.Command{Use: "cdot", Short: "Manage cDOT SSH access"}
	cdot.PersistentFlags().String("user", "pathdiff", "default SSH user for cDOT connections")
	cdot.PersistentFlags().String("host", defaultCDOTCluster(), "cDOT cluster hostname or address")
	pubkey := &cobra.Command{Use: "pubkey", Short: "Manage the cDOT SSH public key"}
	var generateFile string
	generate := &cobra.Command{Use: "generate", Short: "Generate a cDOT SSH public key", RunE: func(command *cobra.Command, _ []string) error {
		keyFile, err := cdotKeyFile(generateFile)
		if err != nil {
			return err
		}
		if err := generateCDOTKey(keyFile); err != nil {
			return err
		}
		_, err = fmt.Fprintln(command.OutOrStdout(), keyFile+".pub")
		return err
	}}
	generate.Flags().StringVar(&generateFile, "file", "", "private key path; defaults to the XDG path")
	var showFile string
	show := &cobra.Command{Use: "show", Short: "Show the cDOT SSH public key", RunE: func(command *cobra.Command, _ []string) error {
		keyFile, err := cdotKeyFile(showFile)
		if err != nil {
			return err
		}
		publicKey, err := os.ReadFile(keyFile + ".pub")
		if err != nil {
			return fmt.Errorf("read cDOT public key: %w", err)
		}
		_, err = fmt.Fprint(command.OutOrStdout(), string(publicKey))
		return err
	}}
	show.Flags().StringVar(&showFile, "file", "", "private key path; defaults to the XDG path")
	pubkey.AddCommand(generate, show)
	cdot.AddCommand(pubkey, newVolumeCommand(), newSVMCommand(), newNodeCommand(), newLIFCommand(), newFPolicyCommand(), newCDOTCheckCommand(), newCDOTSetClusterCommand())
	return cdot
}

func newFPolicyCommand() *cobra.Command {
	fpolicy := &cobra.Command{Use: "fpolicy", Short: "Inspect and manage cDOT FPolicy policies"}
	fpolicy.AddCommand(newFPolicyListCommand(), newFPolicyScopeCommand(), newFPolicyCreateCommand(), newFPolicyStartCommand(), newFPolicyStopCommand())
	return fpolicy
}

func newFPolicyCreateCommand() *cobra.Command {
	var keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec bool
	command := &cobra.Command{Use: "create [<svmWildcardSearch>]", Args: cobra.MaximumNArgs(1), Short: "Print FPolicy setup commands for unconfigured SVMs", RunE: func(command *cobra.Command, arguments []string) error {
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		if host == "" {
			return errors.New("host is required")
		}
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		endpoints, err := pathdiffEndpoints()
		if err != nil {
			return err
		}
		client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		policyOutput, err := runSSHCommand(client, fpolicyPolicyShowCommand+" -instance", debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT FPolicy policies: %w: %s", err, strings.TrimSpace(string(policyOutput)))
		}
		engineOutput, err := runSSHCommand(client, "vserver fpolicy policy external-engine show -instance", debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT FPolicy external engines: %w: %s", err, strings.TrimSpace(string(engineOutput)))
		}
		svmOutput, err := runSSHCommand(client, "vserver show -instance", debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT SVMs: %w: %s", err, strings.TrimSpace(string(svmOutput)))
		}
		sequenceOutput, err := runSSHCommand(client, "vserver fpolicy show -instance", debugWriter)
		if err != nil {
			sequenceOutput = nil
		}
		pattern := "*"
		if len(arguments) == 1 {
			pattern = arguments[0]
		}
		policies := parseFPolicyPolicies(string(policyOutput), string(engineOutput))
		plans, err := fpolicyCreatePlans(parseONTAPInstances(string(svmOutput)), policies, parseONTAPInstances(string(sequenceOutput)), pattern, len(arguments) == 0, endpoints)
		if err != nil {
			return err
		}
		if len(plans) == 0 {
			return errors.New("no unconfigured data SVMs matched")
		}
		return printFPolicyCreateCommands(command.OutOrStdout(), plans)
	}}
	addCDOTConnectionFlags(command, &keyFile, &knownHostsFile, &acceptNewHostKey, &debugSSHExec)
	return command
}

type fpolicyCreatePlan struct {
	SVM      string
	TargetIP string
	Port     string
	Sequence int
}

type expectedFPolicySender struct {
	Port     int
	Sources  map[string]struct{}
	Policies []fpolicyPolicy
}

type fpolicyLIF struct {
	Name    string
	SVM     string
	Node    string
	Address string
}

func discoverFPolicySenders(context context.Context, endpoints []*net.TCPAddr) (map[int]*expectedFPolicySender, error) {
	host := defaultCDOTCluster()
	if host == "" {
		return nil, errors.New("cDOT host is required to discover FPolicy senders")
	}
	keyFile, err := cdotKeyFile("")
	if err != nil {
		return nil, err
	}
	knownHostsFile, err := cdotKnownHostsFile()
	if err != nil {
		return nil, err
	}
	client, err := openCDOTClient(host, "pathdiff", keyFile, knownHostsFile, false)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	policyOutput, err := runSSHCommandContext(context, client, fpolicyPolicyShowCommand+" -instance", nil)
	if err != nil {
		return nil, fmt.Errorf("query cDOT FPolicy policies: %w", err)
	}
	engineOutput, err := runSSHCommandContext(context, client, "vserver fpolicy policy external-engine show -instance", nil)
	if err != nil {
		return nil, fmt.Errorf("query cDOT FPolicy external engines: %w", err)
	}
	lifOutput, err := runSSHCommandContext(context, client, "network interface show -instance", nil)
	if err != nil {
		return nil, fmt.Errorf("query cDOT LIFs: %w", err)
	}
	endpointIPs := make(map[string]struct{}, len(endpoints))
	endpointPorts := make(map[int]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		endpointIPs[endpoint.IP.String()] = struct{}{}
		endpointPorts[endpoint.Port] = struct{}{}
	}
	expected := make(map[int]*expectedFPolicySender)
	for _, policy := range parseFPolicyPolicies(string(policyOutput), string(engineOutput)) {
		port, err := strconv.Atoi(policy.Port)
		if err != nil {
			continue
		}
		if _, found := endpointPorts[port]; !found || !fpolicyTargetsMatch(policy.Targets, endpointIPs) {
			continue
		}
		sender := expected[port]
		if sender == nil {
			sender = &expectedFPolicySender{Port: port, Sources: make(map[string]struct{})}
			expected[port] = sender
		}
		sender.Policies = append(sender.Policies, policy)
	}
	for _, lif := range fpolicyClientLIFs(parseONTAPInstances(string(lifOutput))) {
		for _, sender := range expected {
			for _, policy := range sender.Policies {
				if policy.SVM == lif.SVM {
					sender.Sources[lif.Address] = struct{}{}
					break
				}
			}
		}
	}
	return expected, nil
}

func fpolicyClientLIFs(records []map[string]string) []fpolicyLIF {
	var lifs []fpolicyLIF
	for _, record := range records {
		address := instanceField(record, "Network Address")
		ip := net.ParseIP(address)
		lif := fpolicyLIF{Name: instanceField(record, "Logical Interface Name"), SVM: instanceField(record, "Vserver"), Node: instanceField(record, "Current Node"), Address: address}
		if lif.Name == "" || lif.SVM == "" || ip == nil || ip.To4() == nil || !strings.Contains(strings.ToLower(instanceField(record, "Service List")), "data-fpolicy-client") || !strings.EqualFold(instanceField(record, "Operational Status"), "up") {
			continue
		}
		lifs = append(lifs, lif)
	}
	return lifs
}

func fpolicyTargetsMatch(targets string, expected map[string]struct{}) bool {
	for _, target := range strings.Split(targets, ",") {
		if _, found := expected[strings.TrimSpace(target)]; found {
			return true
		}
	}
	return false
}

func fpolicyCreatePlans(svms []map[string]string, policies []fpolicyPolicy, sequences []map[string]string, pattern string, nfsOnly bool, endpoints []*net.TCPAddr) ([]fpolicyCreatePlan, error) {
	configured := make(map[string]bool)
	policyCount := make(map[string]int)
	for _, policy := range policies {
		policyCount[policy.SVM]++
		if wildcardContains(policy.Name, "pathdiff*") || wildcardContains(policy.Engine, "pathdiff*") {
			configured[policy.SVM] = true
		}
	}
	nextSequence := make(map[string]int)
	for _, record := range sequences {
		svm := instanceField(record, "Vserver")
		sequence, err := strconv.Atoi(firstInstanceField(record, "Sequence Number", "Sequence"))
		if err == nil && sequence >= nextSequence[svm] {
			nextSequence[svm] = sequence + 1
		}
	}
	var plans []fpolicyCreatePlan
	usedPorts := make(map[string]bool)
	for _, policy := range policies {
		if wildcardContains(policy.Name, "pathdiff*") || wildcardContains(policy.Engine, "pathdiff*") {
			usedPorts[policy.Port] = true
		}
	}
	endpointIndex := 0
	for _, record := range svms {
		svm := instanceField(record, "Vserver")
		if svm == "" || configured[svm] || !wildcardContains(svm, pattern) {
			continue
		}
		if vserverType := strings.ToLower(firstInstanceField(record, "Vserver Type", "Type")); vserverType != "" && vserverType != "data" {
			continue
		}
		if nfsOnly && !fpolicySVMHasNFS(record) {
			continue
		}
		for endpointIndex < len(endpoints) && usedPorts[strconv.Itoa(endpoints[endpointIndex].Port)] {
			endpointIndex++
		}
		if endpointIndex == len(endpoints) {
			return nil, errors.New("not enough configured pathdiff listener ports for matching SVMs")
		}
		endpoint := endpoints[endpointIndex]
		endpointIndex++
		sequence := nextSequence[svm]
		if sequence == 0 {
			sequence = policyCount[svm] + 1
		}
		plans = append(plans, fpolicyCreatePlan{SVM: svm, TargetIP: endpoint.IP.String(), Port: strconv.Itoa(endpoint.Port), Sequence: sequence})
	}
	sort.Slice(plans, func(left, right int) bool { return plans[left].SVM < plans[right].SVM })
	return plans, nil
}

func fpolicySVMHasNFS(svm map[string]string) bool {
	for _, protocol := range strings.Split(strings.ToLower(instanceField(svm, "Allowed Protocols")), ",") {
		if strings.TrimSpace(protocol) == "nfs" {
			return true
		}
	}
	return false
}

func pathdiffEndpoints() ([]*net.TCPAddr, error) {
	listenAddr := defaultListen
	if unitPath, err := systemdUserUnitPath(); err == nil {
		if unit, err := os.ReadFile(unitPath); err == nil {
			if match := unitListenPattern.FindStringSubmatch(string(unit)); len(match) == 2 {
				if value, err := strconv.Unquote(match[1]); err == nil {
					listenAddr = value
					if listenAddr == ":9911" {
						listenAddr = defaultListen
					}
				}
			}
		}
	}
	endpoints, err := parseListenAddresses(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("parse pathdiff listener %q: %w", listenAddr, err)
	}
	for _, endpoint := range endpoints {
		if endpoint.IP == nil || endpoint.IP.IsUnspecified() {
			for _, address := range localAddresses() {
				if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
					endpoint.IP = ip
					break
				}
			}
		}
		if endpoint.IP == nil || endpoint.IP.To4() == nil {
			return nil, fmt.Errorf("resolve pathdiff listener IPv4 address from %q", listenAddr)
		}
	}
	return endpoints, nil
}

func printFPolicyCreateCommands(writer io.Writer, plans []fpolicyCreatePlan) error {
	for index, plan := range plans {
		if index > 0 {
			_, _ = fmt.Fprintln(writer)
		}
		_, _ = fmt.Fprintf(writer, "vserver fpolicy policy external-engine create -vserver %s -engine-name pathdiff -primary-servers %s -port %s -ssl-option no-auth -extern-engine-type asynchronous -extern-engine-format xml\n", plan.SVM, plan.TargetIP, plan.Port)
		_, _ = fmt.Fprintf(writer, "vserver fpolicy policy event create -vserver %s -event-name pathdiff_events -protocol nfsv3 -file-operations create,delete,write,rename,setattr -filters first-write,setattr-with-modify-time-change\n", plan.SVM)
		_, _ = fmt.Fprintf(writer, "vserver fpolicy policy create -vserver %s -policy-name pathdiff_policy -events pathdiff_events -engine pathdiff -is-mandatory false\n", plan.SVM)
		_, _ = fmt.Fprintf(writer, "vserver fpolicy policy scope create -vserver %s -policy-name pathdiff_policy -volumes-to-include *\n", plan.SVM)
		_, _ = fmt.Fprintf(writer, "vserver fpolicy enable -vserver %s -policy-name pathdiff_policy -sequence-number %d\n", plan.SVM, plan.Sequence)
	}
	return nil
}

func newFPolicyListCommand() *cobra.Command {
	var keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec, all bool
	command := &cobra.Command{Use: "list [<svmWildcardSearchTerm>]", Args: cobra.MaximumNArgs(1), Short: "List FPolicy external-engine policies", RunE: func(command *cobra.Command, arguments []string) error {
		policies, err := queryFPolicy(command, keyFile, knownHostsFile, acceptNewHostKey, debugSSHExec)
		if err != nil {
			return err
		}
		svmPattern := "*"
		if len(arguments) == 1 {
			svmPattern = arguments[0]
		}
		return printFPolicyPolicies(command.OutOrStdout(), filterFPolicyPolicies(policies, svmPattern, "", all))
	}}
	addCDOTConnectionFlags(command, &keyFile, &knownHostsFile, &acceptNewHostKey, &debugSSHExec)
	command.Flags().BoolVarP(&all, "all", "a", false, "show all FPolicy policies instead of pathdiff*")
	return command
}

func newFPolicyScopeCommand() *cobra.Command {
	var keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec, all bool
	scope := &cobra.Command{Use: "scope", Short: "Inspect cDOT FPolicy policy scopes"}
	list := &cobra.Command{Use: "list [<svmWildcardSearchTerm>]", Args: cobra.MaximumNArgs(1), Short: "List FPolicy policy scopes", RunE: func(command *cobra.Command, arguments []string) error {
		policies, err := queryFPolicy(command, keyFile, knownHostsFile, acceptNewHostKey, debugSSHExec)
		if err != nil {
			return err
		}
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		output, err := runSSHCommand(client, "vserver fpolicy policy scope show -instance", debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT FPolicy scopes: %w: %s", err, strings.TrimSpace(string(output)))
		}
		svmPattern := "*"
		if len(arguments) == 1 {
			svmPattern = arguments[0]
		}
		return printFPolicyScopes(command.OutOrStdout(), filterFPolicyScopes(parseFPolicyScopes(string(output), policies), svmPattern, all))
	}}
	addCDOTConnectionFlags(list, &keyFile, &knownHostsFile, &acceptNewHostKey, &debugSSHExec)
	list.Flags().BoolVarP(&all, "all", "a", false, "show all FPolicy policies instead of pathdiff*")
	scope.AddCommand(list)
	return scope
}

func newFPolicyStartCommand() *cobra.Command {
	return newFPolicyActionCommand("start", "enable")
}

func newFPolicyStopCommand() *cobra.Command {
	return newFPolicyActionCommand("stop", "disable")
}

func newFPolicyActionCommand(action, ontapAction string) *cobra.Command {
	var controlPath, keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec, all bool
	command := &cobra.Command{Use: action + " [<svmWildcardSearchTerm> [<policyClass>]]", Args: cobra.MaximumNArgs(2), Short: strings.ToUpper(action[:1]) + action[1:] + " FPolicy policy classes", RunE: func(command *cobra.Command, arguments []string) error {
		policies, err := queryFPolicy(command, keyFile, knownHostsFile, acceptNewHostKey, debugSSHExec)
		if err != nil {
			return err
		}
		svmPattern, policyPattern := "*", ""
		if len(arguments) > 0 {
			svmPattern = arguments[0]
		}
		if len(arguments) > 1 {
			policyPattern = arguments[1]
		}
		selected := filterFPolicyPolicies(policies, svmPattern, policyPattern, all)
		if len(selected) == 0 {
			return errors.New("no matching FPolicy policy classes")
		}
		if ontapAction == "enable" {
			if _, err := callControl(controlPath, controlRequest{Command: "fpolicy-refresh"}); err != nil {
				return fmt.Errorf("ensure pathdiff is listening for FPolicy policies: %w", err)
			}
		}
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		for _, policy := range selected {
			if ontapAction == "enable" {
				if err := enableFPolicyPolicy(command.Context(), nil, client, policy, debugWriter); err != nil {
					return err
				}
				continue
			}
			remoteCommand := "vserver fpolicy " + ontapAction + " -vserver " + shellQuote(policy.SVM) + " -policy-name " + shellQuote(policy.Name)
			output, err := runSSHCommand(client, remoteCommand, debugWriter)
			if err != nil {
				return fmt.Errorf("%s FPolicy policy %s on %s: %w: %s", action, policy.Name, policy.SVM, err, strings.TrimSpace(string(output)))
			}
		}
		state := action + "ed"
		if action == "stop" {
			state = "stopped"
		}
		return printFPolicyAction(command.OutOrStdout(), selected, state)
	}}
	addCDOTConnectionFlags(command, &keyFile, &knownHostsFile, &acceptNewHostKey, &debugSSHExec)
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	command.Flags().BoolVarP(&all, "all", "a", false, action+" all matching FPolicy policies instead of pathdiff*")
	return command
}

func enableFPolicyPolicy(context context.Context, db *store.DB, client *ssh.Client, policy fpolicyPolicy, debugWriter io.Writer) error {
	if err := context.Err(); err != nil {
		return err
	}
	if err := verifyFPolicyReachability(context, db, client, policy, debugWriter); err != nil {
		return err
	}
	disableCommand := "vserver fpolicy disable -vserver " + shellQuote(policy.SVM) + " -policy-name " + shellQuote(policy.Name)
	disableOutput, err := runSSHCommand(client, disableCommand, debugWriter)
	if err != nil && !strings.Contains(strings.ToLower(string(disableOutput)), "not enabled") {
		return fmt.Errorf("could not disable the existing policy before restart: %s", ontapErrorDetail(disableOutput))
	}
	enabled := false
	for sequence := 1; sequence <= 1000; sequence++ {
		if err := context.Err(); err != nil {
			return err
		}
		remoteCommand := "vserver fpolicy enable -vserver " + shellQuote(policy.SVM) + " -policy-name " + shellQuote(policy.Name) + " -sequence-number " + strconv.Itoa(sequence)
		output, err := runSSHCommand(client, remoteCommand, debugWriter)
		if err == nil || strings.Contains(strings.ToLower(string(output)), "already enabled") {
			enabled = true
			break
		}
		if !fpolicySequenceConflict(string(output)) {
			return fmt.Errorf("could not enable with sequence number %d: %s", sequence, ontapErrorDetail(output))
		}
	}
	if !enabled {
		return errors.New("no free sequence number was found after trying 1 through 1000")
	}
	if err := connectFPolicyEngine(client, policy, debugWriter); err != nil {
		return err
	}
	return waitForFPolicyConnection(context, client, policy, debugWriter, 30*time.Second)
}

func verifyFPolicyReachability(context context.Context, db *store.DB, client *ssh.Client, policy fpolicyPolicy, debugWriter io.Writer) error {
	output, err := runSSHCommand(client, "network interface show -instance", debugWriter)
	if err != nil {
		return fmt.Errorf("could not list FPolicy-client LIFs before activation: %s", ontapErrorDetail(output))
	}
	var lifs []fpolicyLIF
	for _, lif := range fpolicyClientLIFs(parseONTAPInstances(string(output))) {
		if lif.SVM == policy.SVM {
			lifs = append(lifs, lif)
		}
	}
	if len(lifs) == 0 {
		return errors.New("no operational data-fpolicy-client LIF was found; activation will not be attempted")
	}
	for _, target := range strings.Split(policy.Targets, ",") {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for _, lif := range lifs {
			if err := context.Err(); err != nil {
				return err
			}
			if db != nil {
				unreachable, err := db.FPolicyLIFUnreachable(lif.SVM, lif.Name, lif.Address)
				if err != nil {
					return err
				}
				if unreachable {
					return &fpolicyReachabilityError{LIF: lif, Target: target, Known: true, Reason: "previously marked unreachable; will not retry until cDOT reports a new LIF address"}
				}
			}
			if err := pingFPolicyReceiver(context, client, lif, target, debugWriter); err != nil {
				if db != nil {
					if markErr := db.MarkFPolicyLIFUnreachable(lif.SVM, lif.Name, lif.Address); markErr != nil {
						return fmt.Errorf("%w; could not persist unreachable state: %v", err, markErr)
					}
				}
				return err
			}
		}
	}
	return nil
}

type fpolicyReachabilityError struct {
	LIF    fpolicyLIF
	Target string
	Known  bool
	Reason string
}

func (e *fpolicyReachabilityError) Error() string {
	return fmt.Sprintf("receiver unreachable from lif=%s addr=%s svm=%s node=%s: %s", e.LIF.Name, e.LIF.Address, e.LIF.SVM, e.LIF.Node, e.Reason)
}

func pingFPolicyReceiver(context context.Context, client *ssh.Client, lif fpolicyLIF, target string, debugWriter io.Writer) error {
	for attempt := 1; attempt <= 5; attempt++ {
		if err := context.Err(); err != nil {
			return err
		}
		command := "network ping -lif " + shellQuote(lif.Name) + " -vserver " + shellQuote(lif.SVM) + " -destination " + shellQuote(target) + " -count 1 -wait 1 -wait-response 1000 -show-detail true"
		output, err := runSSHCommand(client, command, debugWriter)
		if err == nil && fpolicyPingSucceeded(output) {
			return nil
		}
		if attempt == 5 {
			reason := "cDOT-to-receiver ping failed after 5 attempts"
			if receiverCanPingLIF(context, lif.Address) {
				reason += "; receiver-to-LIF ping succeeded, so a one-way firewall or routing policy is likely"
			} else {
				reason += "; receiver-to-LIF ping also failed, so this LIF is likely on an isolated private network"
			}
			return &fpolicyReachabilityError{LIF: lif, Target: target, Reason: reason}
		}
		delay := time.Second * time.Duration(1<<(attempt-1))
		select {
		case <-context.Done():
			return context.Err()
		case <-time.After(delay):
		}
	}
	return nil
}

func receiverCanPingLIF(context context.Context, address string) bool {
	command := exec.CommandContext(context, "ping", "-c", "1", "-W", "1", address)
	return command.Run() == nil
}

func fpolicyPingSucceeded(output []byte) bool {
	match := pingPacketsPattern.FindStringSubmatch(string(output))
	if len(match) != 2 {
		return false
	}
	received, err := strconv.Atoi(match[1])
	return err == nil && received > 0
}

func connectFPolicyEngine(client *ssh.Client, policy fpolicyPolicy, debugWriter io.Writer) error {
	nodeOutput, err := runSSHCommand(client, "node show -instance", debugWriter)
	if err != nil {
		return fmt.Errorf("could not list cluster nodes before connecting the external engine: %s", ontapErrorDetail(nodeOutput))
	}
	for _, node := range parseONTAPInstances(string(nodeOutput)) {
		name := instanceField(node, "Node")
		if name == "" {
			continue
		}
		for _, server := range strings.Split(policy.Targets, ",") {
			server = strings.TrimSpace(server)
			if server == "" {
				continue
			}
			remoteCommand := "vserver fpolicy engine-connect -vserver " + shellQuote(policy.SVM) + " -policy-name " + shellQuote(policy.Name) + " -node " + shellQuote(name) + " -server " + shellQuote(server)
			output, err := runSSHCommand(client, remoteCommand, debugWriter)
			if err != nil && !fpolicyAlreadyConnected(string(output)) {
				return fmt.Errorf("could not connect node %s to receiver %s: %s", name, server, ontapErrorDetail(output))
			}
		}
	}
	return nil
}

func waitForFPolicyConnection(context context.Context, client *ssh.Client, policy fpolicyPolicy, debugWriter io.Writer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := context.Err(); err != nil {
			return err
		}
		remoteCommand := "vserver fpolicy show-engine -vserver " + shellQuote(policy.SVM) + " -policy-name " + shellQuote(policy.Name) + " -fields vserver,policy-name,server-status"
		output, err := runSSHCommand(client, remoteCommand, debugWriter)
		if err != nil {
			return fmt.Errorf("could not read engine connection state: %s", ontapErrorDetail(output))
		}
		statuses := parseFPolicyEngineStates(string(output))[policy.SVM+"\x00"+policy.Name]
		if fpolicyEngineConnected(statuses) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("receiver handshake did not complete within %s", timeout)
		}
		select {
		case <-context.Done():
			return context.Err()
		case <-time.After(time.Second):
		}
	}
}

func fpolicyAlreadyConnected(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "already connected") || (strings.Contains(output, "specified server") && strings.Contains(output, "connected"))
}

func ontapErrorDetail(output []byte) string {
	ansi := ansiEscapePattern.ReplaceAll(output, nil)
	lines := make([]string, 0)
	for _, line := range strings.Split(string(ansi), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last login time:") || strings.Contains(line, "blob data") {
			continue
		}
		lines = append(lines, line)
	}
	detail := strings.Join(strings.Fields(strings.Join(lines, " ")), " ")
	detail = strings.TrimPrefix(detail, "Error: command failed: ")
	detail = strings.TrimPrefix(detail, "Error: ")
	if detail == "" {
		return "ONTAP returned no error detail"
	}
	return detail
}

func fpolicyEngineConnected(statuses []string) bool {
	if len(statuses) == 0 {
		return false
	}
	for _, status := range statuses {
		if !strings.EqualFold(status, "connected") {
			return false
		}
	}
	return true
}

func fpolicySequenceConflict(output string) bool {
	output = strings.ToLower(output)
	return strings.Contains(output, "sequence") && (strings.Contains(output, "already") || strings.Contains(output, "in use") || strings.Contains(output, "exists"))
}

type fpolicyPolicy struct {
	SVM     string
	Name    string
	Engine  string
	State   string
	Targets string
	Port    string
	SSL     string
	Type    string
	Format  string
	Events  string
}

type fpolicyScope struct {
	SVM           string
	Engine        string
	Policy        string
	VolumeExcl    string
	VolumeIncl    string
	ShareExcl     string
	ShareIncl     string
	ExtensionExcl string
	ExtensionIncl string
	ExportExcl    string
	ExportIncl    string
}

func addCDOTConnectionFlags(command *cobra.Command, keyFile, knownHostsFile *string, acceptNewHostKey, debugSSHExec *bool) {
	command.Flags().StringVar(keyFile, "key", "", "private key path; defaults to the XDG path")
	command.Flags().StringVar(knownHostsFile, "known-hosts", "", "known_hosts file; defaults to the XDG path")
	command.Flags().BoolVar(acceptNewHostKey, "accept-new-host-key", false, "trust and save the host key when known_hosts is absent")
	command.Flags().BoolVar(debugSSHExec, "debug-ssh-exec", false, "print SSH commands and their results to stderr")
}

func queryFPolicy(command *cobra.Command, keyFile, knownHostsFile string, acceptNewHostKey, debugSSHExec bool) ([]fpolicyPolicy, error) {
	host, _ := command.Flags().GetString("host")
	user, _ := command.Flags().GetString("user")
	if host == "" {
		return nil, errors.New("host is required")
	}
	keyPath, err := cdotKeyFile(keyFile)
	if err != nil {
		return nil, err
	}
	if knownHostsFile == "" {
		knownHostsFile, err = cdotKnownHostsFile()
		if err != nil {
			return nil, err
		}
	}
	client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	var debugWriter io.Writer
	if debugSSHExec {
		debugWriter = command.ErrOrStderr()
	}
	policyOutput, err := runSSHCommand(client, fpolicyPolicyShowCommand+" -instance", debugWriter)
	if err != nil {
		return nil, fmt.Errorf("query cDOT FPolicy policies: %w: %s", err, strings.TrimSpace(string(policyOutput)))
	}
	engineOutput, err := runSSHCommand(client, "vserver fpolicy policy external-engine show -instance", debugWriter)
	if err != nil {
		return nil, fmt.Errorf("query cDOT FPolicy external engines: %w: %s", err, strings.TrimSpace(string(engineOutput)))
	}
	policies := parseFPolicyPolicies(string(policyOutput), string(engineOutput))
	stateOutput, err := runSSHCommand(client, "vserver fpolicy show-engine -fields vserver,policy-name,server-status", debugWriter)
	if err != nil {
		return policies, nil
	}
	applyFPolicyEngineStates(policies, parseFPolicyEngineStates(string(stateOutput)))
	return policies, nil
}

func parseFPolicyEngineStates(output string) map[string][]string {
	states := make(map[string][]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] == "node" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		key := fields[1] + "\x00" + fields[2]
		states[key] = append(states[key], fields[4])
	}
	return states
}

func applyFPolicyEngineStates(policies []fpolicyPolicy, states map[string][]string) {
	for index := range policies {
		statuses := states[policies[index].SVM+"\x00"+policies[index].Name]
		if len(statuses) == 0 {
			continue
		}
		policies[index].State = "off"
		for _, status := range statuses {
			if strings.EqualFold(status, "connected") {
				policies[index].State = "connected"
				break
			}
		}
	}
}

func parseFPolicyPolicies(policyOutput, engineOutput string) []fpolicyPolicy {
	engines := make(map[string]map[string]string)
	for _, record := range parseONTAPInstances(engineOutput) {
		engines[fpolicyRecordKey(record, "Engine", "External Engine Name", "Engine Name", "Name")] = record
	}
	var policies []fpolicyPolicy
	for _, record := range parseONTAPInstances(policyOutput) {
		engineName := firstInstanceField(record, "FPolicy Engine", "External Engine Name", "Engine Name")
		if engineName == "" {
			continue
		}
		engine := engines[instanceField(record, "Vserver")+"\x00"+engineName]
		eventNames := firstInstanceField(record, "Events To Monitor", "Event Names", "Event Name")
		policies = append(policies, fpolicyPolicy{
			SVM:     instanceField(record, "Vserver"),
			Name:    firstInstanceField(record, "Policy", "Policy Name", "Name"),
			Engine:  engineName,
			State:   "unknown",
			Targets: fpolicyTargets(engine),
			Port:    firstInstanceField(engine, "Port Number of FPolicy Service", "Port"),
			SSL:     firstInstanceField(engine, "SSL Option for External Communication", "SSL Option", "SSL"),
			Type:    firstInstanceField(engine, "Type", "External Engine Type"),
			Format:  firstInstanceField(engine, "External Engine Format", "Format"),
			Events:  eventNames,
		})
	}
	sort.Slice(policies, func(left, right int) bool {
		return policies[left].SVM+"\x00"+policies[left].Name < policies[right].SVM+"\x00"+policies[right].Name
	})
	return policies
}

func fpolicyRecordKey(record map[string]string, names ...string) string {
	return instanceField(record, "Vserver") + "\x00" + firstInstanceField(record, names...)
}

func firstInstanceField(record map[string]string, names ...string) string {
	for _, name := range names {
		if value := instanceField(record, name); value != "" {
			return value
		}
	}
	return ""
}

func fpolicyTargets(engine map[string]string) string {
	var targets []string
	for _, target := range []string{
		firstInstanceField(engine, "Primary FPolicy Servers", "Primary Servers", "Primary Server", "Servers"),
		firstInstanceField(engine, "Secondary FPolicy Servers", "Secondary Servers", "Secondary Server"),
	} {
		if target != "" && target != "-" {
			targets = append(targets, target)
		}
	}
	return strings.Join(targets, ", ")
}

func filterFPolicyPolicies(policies []fpolicyPolicy, svmPattern, policyPattern string, all bool) []fpolicyPolicy {
	var filtered []fpolicyPolicy
	for _, policy := range policies {
		if !wildcardContains(policy.SVM, svmPattern) {
			continue
		}
		if policyPattern != "" && !wildcardContains(policy.Name, policyPattern) {
			continue
		}
		if !all && !wildcardContains(policy.Name, "pathdiff*") && !wildcardContains(policy.Engine, "pathdiff*") {
			continue
		}
		filtered = append(filtered, policy)
	}
	return filtered
}

func wildcardContains(value, pattern string) bool {
	value, pattern = strings.ToLower(value), strings.ToLower(pattern)
	if !strings.ContainsAny(pattern, "*?") {
		pattern = "*" + pattern + "*"
	}
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

func printFPolicyPolicies(writer io.Writer, policies []fpolicyPolicy) error {
	sort.Slice(policies, func(left, right int) bool {
		leftSVM, rightSVM := strings.ToLower(policies[left].SVM), strings.ToLower(policies[right].SVM)
		if leftSVM == rightSVM {
			return strings.ToLower(policies[left].Name) < strings.ToLower(policies[right].Name)
		}
		return leftSVM < rightSVM
	})
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"SVM", "Engine", "State", "Targets", "Port", "SSL", "Type", "Format", "Policy Class", "Event Class"})
	for _, policy := range policies {
		tableWriter.AppendRow(table.Row{policy.SVM, policy.Engine, formatFPolicyState(policy.State), policy.Targets, policy.Port, policy.SSL, policy.Type, policy.Format, policy.Name, policy.Events})
	}
	tableWriter.Render()
	return nil
}

func parseFPolicyScopes(output string, policies []fpolicyPolicy) []fpolicyScope {
	engines := make(map[string]string)
	for _, policy := range policies {
		engines[policy.SVM+"\x00"+policy.Name] = policy.Engine
	}
	var scopes []fpolicyScope
	for _, record := range parseONTAPInstances(output) {
		svm := instanceField(record, "Vserver")
		policy := firstInstanceField(record, "Policy", "Policy Name", "Name")
		scopes = append(scopes, fpolicyScope{
			SVM:           svm,
			Engine:        engines[svm+"\x00"+policy],
			Policy:        policy,
			VolumeExcl:    instanceField(record, "Volumes to Exclude"),
			VolumeIncl:    instanceField(record, "Volumes to Include"),
			ShareExcl:     instanceField(record, "Shares to Exclude"),
			ShareIncl:     instanceField(record, "Shares to Include"),
			ExtensionExcl: instanceField(record, "File Extensions to Exclude"),
			ExtensionIncl: instanceField(record, "File Extensions to Include"),
			ExportExcl:    instanceField(record, "Export Policies to Exclude"),
			ExportIncl:    instanceField(record, "Export Policies to Include"),
		})
	}
	return scopes
}

func filterFPolicyScopes(scopes []fpolicyScope, svmPattern string, all bool) []fpolicyScope {
	var filtered []fpolicyScope
	for _, scope := range scopes {
		if wildcardContains(scope.SVM, svmPattern) && (all || wildcardContains(scope.Policy, "pathdiff*") || wildcardContains(scope.Engine, "pathdiff*")) {
			filtered = append(filtered, scope)
		}
	}
	return filtered
}

func printFPolicyScopes(writer io.Writer, scopes []fpolicyScope) error {
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"SVM", "Engine", "Policy Class", "Vol Excl", "Vol Incl", "Share Excl", "Share Incl", "Ext Excl", "Ext Incl", "Export Excl", "Export Incl"})
	for _, scope := range scopes {
		tableWriter.AppendRow(table.Row{scope.SVM, scope.Engine, scope.Policy, formatFPolicyScopeValue(scope.VolumeExcl, text.FgYellow, true), formatFPolicyScopeValue(scope.VolumeIncl, text.FgGreen, true), formatFPolicyScopeValue(scope.ShareExcl, text.FgBlack, false), formatFPolicyScopeValue(scope.ShareIncl, text.FgBlack, false), formatFPolicyScopeValue(scope.ExtensionExcl, text.FgBlack, false), formatFPolicyScopeValue(scope.ExtensionIncl, text.FgBlack, false), formatFPolicyScopeValue(scope.ExportExcl, text.FgBlack, false), formatFPolicyScopeValue(scope.ExportIncl, text.FgBlack, false)})
	}
	tableWriter.Render()
	return nil
}

func formatFPolicyScopeValue(value string, color text.Color, highlight bool) string {
	if value == "-" {
		return text.FgHiBlack.Sprint(value)
	}
	if highlight {
		return color.Sprint(value)
	}
	return value
}

func printFPolicyAction(writer io.Writer, policies []fpolicyPolicy, state string) error {
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"SVM", "Policy Class", "State"})
	for _, policy := range policies {
		tableWriter.AppendRow(table.Row{policy.SVM, policy.Name, state})
	}
	tableWriter.Render()
	return nil
}

func newCDOTSetClusterCommand() *cobra.Command {
	return &cobra.Command{Use: "set-cluster <clusterFQDN>", Args: cobra.ExactArgs(1), Short: "Set the default cDOT cluster", RunE: func(command *cobra.Command, arguments []string) error {
		if err := setCDOTCluster(arguments[0]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(command.OutOrStdout(), arguments[0])
		return err
	}}
}

func newCDOTCheckCommand() *cobra.Command {
	var keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec bool
	command := &cobra.Command{Use: "check", Short: "Check cDOT FPolicy external-engine configuration", RunE: func(command *cobra.Command, _ []string) error {
		host, err := command.Flags().GetString("host")
		if err != nil {
			return err
		}
		user, err := command.Flags().GetString("user")
		if err != nil {
			return err
		}
		if host == "" {
			return errors.New("host is required")
		}
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		result, err := checkCDOT(host, user, keyPath, knownHostsFile, acceptNewHostKey, debugWriter)
		if err != nil {
			return err
		}
		return printCDOTCheck(command.OutOrStdout(), result)
	}}
	command.Flags().StringVar(&keyFile, "key", "", "private key path; defaults to the XDG path")
	command.Flags().StringVar(&knownHostsFile, "known-hosts", "", "known_hosts file; defaults to the XDG path")
	command.Flags().BoolVar(&acceptNewHostKey, "accept-new-host-key", false, "trust and save the host key when known_hosts is absent")
	command.Flags().BoolVar(&debugSSHExec, "debug-ssh-exec", false, "print SSH commands and their results to stderr")
	return command
}

type cdotCheckResult struct {
	Host            string
	User            string
	FPolicyPolicy   string
	FPolicyEndpoint string
}

func checkCDOT(host, user, keyFile, knownHostsFile string, acceptNewHostKey bool, debugWriter io.Writer) (cdotCheckResult, error) {
	client, err := openCDOTClient(host, user, keyFile, knownHostsFile, acceptNewHostKey)
	if err != nil {
		return cdotCheckResult{}, err
	}
	defer client.Close()
	output, err := runSSHCommand(client, fpolicyPolicyShowCommand, debugWriter)
	if err != nil {
		return cdotCheckResult{}, fmt.Errorf("query cDOT FPolicy policies: %w: %s", err, strings.TrimSpace(string(output)))
	}
	policy := "readable"
	if strings.TrimSpace(string(output)) == "" {
		policy = "no policies returned"
	}
	output, err = runSSHCommand(client, fpolicyEngineShowCommand, debugWriter)
	if err != nil {
		return cdotCheckResult{}, fmt.Errorf("query cDOT FPolicy external engines: %w: %s", err, strings.TrimSpace(string(output)))
	}
	endpoint := "not configured for this host"
	if fpolicyServerMatches(string(output), localAddresses()) {
		endpoint = "configured for this host"
	}
	return cdotCheckResult{Host: host, User: user, FPolicyPolicy: policy, FPolicyEndpoint: endpoint}, nil
}

func openCDOTClient(host, user, keyFile, knownHostsFile string, acceptNewHostKey bool) (*ssh.Client, error) {
	signer, err := readSSHSigner(keyFile)
	if err != nil {
		return nil, err
	}
	address := sshAddress(host)
	hostKeyCallback, err := cdotHostKeyCallback(knownHostsFile, address, acceptNewHostKey)
	if err != nil {
		return nil, fmt.Errorf("load cDOT known hosts: %w", err)
	}
	connection, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to cDOT %s: %w", address, err)
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: hostKeyCallback, Timeout: 10 * time.Second})
	if err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("authenticate to cDOT %s: %w", address, err)
	}
	return ssh.NewClient(clientConnection, channels, requests), nil
}

func runSSHCommand(client *ssh.Client, command string, debugWriter io.Writer) ([]byte, error) {
	if debugWriter != nil {
		_, _ = fmt.Fprintf(debugWriter, "ssh exec: %s\n", command)
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	if debugWriter != nil {
		_, _ = fmt.Fprintf(debugWriter, "ssh result:\n%s\n", output)
	}
	return output, err
}

func runSSHCommandContext(context context.Context, client *ssh.Client, command string, debugWriter io.Writer) ([]byte, error) {
	if err := context.Err(); err != nil {
		return nil, err
	}
	if debugWriter != nil {
		_, _ = fmt.Fprintf(debugWriter, "ssh exec: %s\n", command)
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	type result struct {
		output []byte
		err    error
	}
	results := make(chan result, 1)
	go func() {
		output, err := session.CombinedOutput(command)
		results <- result{output: output, err: err}
	}()
	select {
	case result := <-results:
		_ = session.Close()
		if debugWriter != nil {
			_, _ = fmt.Fprintf(debugWriter, "ssh result:\n%s\n", result.output)
		}
		return result.output, result.err
	case <-context.Done():
		_ = session.Close()
		return nil, context.Err()
	}
}

func cdotHostKeyCallback(knownHostsFile, address string, acceptNewHostKey bool) (ssh.HostKeyCallback, error) {
	callback, err := knownhosts.New(knownHostsFile)
	if err == nil {
		return callback, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !acceptNewHostKey {
		return nil, fmt.Errorf("load cDOT known hosts: %w; run cdot check with --accept-new-host-key to trust the first key", err)
	}
	if err := os.MkdirAll(filepath.Dir(knownHostsFile), 0o700); err != nil {
		return nil, err
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		file, err := os.OpenFile(knownHostsFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = file.WriteString(knownhosts.Line([]string{knownhosts.Normalize(address)}, key) + "\n")
		return err
	}, nil
}

func readSSHSigner(keyFile string) (ssh.Signer, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read cDOT SSH private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse cDOT SSH private key: %w", err)
	}
	return signer, nil
}

func cdotKnownHostsFile() (string, error) {
	configHome, err := cdotConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(configHome, "known_hosts"), nil
}

type cdotConfig struct {
	Cluster string `json:"cluster"`
}

func defaultCDOTCluster() string {
	config, err := loadCDOTConfig()
	if err != nil {
		return ""
	}
	return config.Cluster
}

func setCDOTCluster(cluster string) error {
	if cluster == "" {
		return errors.New("cluster FQDN is required")
	}
	configPath, err := cdotConfigFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(cdotConfig{Cluster: cluster})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(configPath), ".cdot.json-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, configPath)
}

func loadCDOTConfig() (cdotConfig, error) {
	configPath, err := cdotConfigFile()
	if err != nil {
		return cdotConfig{}, err
	}
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return cdotConfig{}, nil
	}
	if err != nil {
		return cdotConfig{}, err
	}
	var config cdotConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return cdotConfig{}, fmt.Errorf("parse cDOT config: %w", err)
	}
	return config, nil
}

func cdotConfigFile() (string, error) {
	configHome, err := cdotConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(configHome, "cdot.json"), nil
}

func cdotConfigHome() (string, error) {
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "pathdiff"), nil
}

func sshAddress(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "22")
}

func localAddresses() []string {
	addresses := []string{}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		addresses = append(addresses, hostname)
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return addresses
	}
	for _, address := range interfaces {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && !ip.IsLoopback() {
			addresses = append(addresses, ip.String())
		}
	}
	return addresses
}

func fpolicyServerMatches(configuration string, addresses []string) bool {
	for _, address := range addresses {
		if strings.Contains(configuration, address) {
			return true
		}
	}
	return false
}

func printCDOTCheck(writer io.Writer, result cdotCheckResult) error {
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Cluster", "SSH User", "FPolicy Policy", "FPolicy Endpoint"})
	tableWriter.AppendRow(table.Row{result.Host, result.User, result.FPolicyPolicy, result.FPolicyEndpoint})
	tableWriter.Render()
	return nil
}

func cdotKeyFile(override string) (string, error) {
	if override != "" {
		return filepath.Abs(override)
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "pathdiff", "cdot_ed25519"), nil
}

func generateCDOTKey(keyFile string) error {
	if _, err := os.Stat(keyFile); err == nil {
		return fmt.Errorf("cDOT SSH key already exists at %s", keyFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate cDOT SSH key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode cDOT SSH private key: %w", err)
	}
	privateFile, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create cDOT SSH private key: %w", err)
	}
	if err := pem.Encode(privateFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}); err != nil {
		_ = privateFile.Close()
		_ = os.Remove(keyFile)
		return fmt.Errorf("write cDOT SSH private key: %w", err)
	}
	if err := privateFile.Close(); err != nil {
		_ = os.Remove(keyFile)
		return fmt.Errorf("close cDOT SSH private key: %w", err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		_ = os.Remove(keyFile)
		return fmt.Errorf("encode cDOT SSH public key: %w", err)
	}
	publicFile, err := os.OpenFile(keyFile+".pub", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = os.Remove(keyFile)
		return fmt.Errorf("create cDOT SSH public key: %w", err)
	}
	if _, err := publicFile.Write(ssh.MarshalAuthorizedKey(sshPublicKey)); err != nil {
		_ = publicFile.Close()
		_ = os.Remove(keyFile + ".pub")
		_ = os.Remove(keyFile)
		return fmt.Errorf("write cDOT SSH public key: %w", err)
	}
	if err := publicFile.Close(); err != nil {
		_ = os.Remove(keyFile + ".pub")
		_ = os.Remove(keyFile)
		return fmt.Errorf("close cDOT SSH public key: %w", err)
	}
	return nil
}

func printEngines(writer io.Writer, engines []engineInfo) error {
	sort.Slice(engines, func(left, right int) bool {
		leftSVM, rightSVM := strings.ToLower(engineSVM(engines[left])), strings.ToLower(engineSVM(engines[right]))
		if leftSVM == rightSVM {
			return engines[left].LIFIPv4 < engines[right].LIFIPv4
		}
		return leftSVM < rightSVM
	})
	maxRate := 0.0
	for _, engine := range engines {
		if engine.AverageRate > maxRate {
			maxRate = engine.AverageRate
		}
	}
	tableWriter := newTableWriter(writer)
	tableWriter.SetColumnConfigs([]table.ColumnConfig{
		{Name: "Port", Align: text.AlignRight, AlignHeader: text.AlignRight},
		{Name: "Last Seen", Align: text.AlignRight, AlignHeader: text.AlignRight},
		{Name: "Avg Event/s", Align: text.AlignRight, AlignHeader: text.AlignRight},
		{Name: "Total Events", Align: text.AlignRight, AlignHeader: text.AlignRight},
	})
	tableWriter.AppendHeader(table.Row{"SVM", "Node", "LIF", "Port", "State", "Last Seen", "Up Since", "Avg Event/s", "Graph", "Total Events"})
	for _, engine := range engines {
		engine.LIFHostname = shortHostname(resolveHostname(engine.LIFIPv4))
		node, svm := engine.NodeName, engineSVM(engine)
		if node == "" {
			node = engine.NodeID
		}
		tableWriter.AppendRow(table.Row{svm, node, engine.LIFHostname, engine.LocalPort, formatFPolicyState(engine.FPolicy), formatLastSeen(engine.LastSeen), engine.Since.UTC().Format(time.RFC3339), formatEventRate(engine.AverageRate), formatMetricGraphCell(engine.AverageRate, maxRate, 6), formatEngineEventCount(engine.TotalEvents)})
	}
	tableWriter.Render()
	return nil
}

func engineSVM(engine engineInfo) string {
	if engine.SVMName != "" {
		return engine.SVMName
	}
	return engine.SVMID
}

func formatEventRate(rate float64) string {
	if rate == 0 {
		return text.FgHiBlack.Sprint("-")
	}
	return fmt.Sprintf("%.2f", rate)
}

func formatEngineEventCount(count uint64) string {
	if count == 0 {
		return text.FgHiBlack.Sprint("-")
	}
	return formatEventCount(count)
}

func formatMetricGraphCell(value, maxValue float64, width int) string {
	if width <= 0 {
		return ""
	}
	if value <= 0 || maxValue <= 0 {
		return strings.Repeat(" ", width)
	}
	filled := int(math.Round(value * float64(width) / maxValue))
	if filled < 1 {
		filled = 1
	}
	if filled > width {
		filled = width
	}
	shade := 238
	if maxValue > 1 {
		shade = 238 + int(math.Round((value-1)*17.0/(maxValue-1)))
	}
	if shade > 255 {
		shade = 255
	}
	return fmt.Sprintf("\033[38;5;%dm%s\033[0m", shade, strings.Repeat("▄", filled)) + strings.Repeat(" ", width-filled)
}

func formatLastSeen(lastSeen time.Time) string {
	if lastSeen.IsZero() {
		return text.FgYellow.Sprint("never")
	}
	return time.Since(lastSeen).Round(time.Second).String() + " ago"
}

func formatFPolicyState(state string) string {
	if state == "" || state == "unavailable" || strings.EqualFold(state, "disconnected") || strings.EqualFold(state, "off") {
		return text.FgRed.Sprint("off")
	}
	if strings.EqualFold(state, "connected") {
		return text.FgGreen.Sprint("connected")
	}
	return state
}

func resolveHostname(address string) string {
	names, err := net.LookupAddr(address)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func shortHostname(hostname string) string {
	return strings.SplitN(hostname, ".", 2)[0]
}

func printDBStatus(writer io.Writer, response controlResponse) error {
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Path", "Size"})
	tableWriter.AppendRow(table.Row{response.DBPath, formatBytes(response.DBSize)})
	tableWriter.Render()
	return nil
}

func newVolumeCommand() *cobra.Command {
	return newCDOTListCommand("volume", "MSID", "List live cDOT volumes", "volume show -fields vserver,volume,msid", "Volume", "MSID")
}

func newSVMCommand() *cobra.Command {
	return newCDOTListCommand("svm", "UUID", "List live cDOT SVMs", "vserver show -instance", "Vserver", "Vserver UUID")
}

func newNodeCommand() *cobra.Command {
	return newCDOTInventoryCommand("node", "List live cDOT nodes", "node show -instance", []string{"Node"})
}

func newLIFCommand() *cobra.Command {
	group := &cobra.Command{Use: "lif", Short: "List live cDOT LIFs"}
	var keyFile, knownHostsFile, svm, node, subnet string
	var acceptNewHostKey, debugSSHExec, all bool
	list := &cobra.Command{Use: "list [<svmWildcardSearchTerm>]", Args: cobra.MaximumNArgs(1), Short: "List live cDOT LIFs", RunE: func(command *cobra.Command, arguments []string) error {
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		if host == "" {
			return errors.New("host is required")
		}
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		output, err := runSSHCommand(client, "network interface show -instance", debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT LIFs: %w: %s", err, strings.TrimSpace(string(output)))
		}
		records := parseONTAPInstances(string(output))
		if !all {
			records = reachableLIFs(records)
		}
		if len(arguments) == 1 {
			records = filterLIFs(records, arguments[0], "", "")
		}
		records = filterLIFs(records, svm, node, subnet)
		return printONTAPInventory(command.OutOrStdout(), []string{"Network Address", "Current Node", "Vserver"}, records)
	}}
	addCDOTConnectionFlags(list, &keyFile, &knownHostsFile, &acceptNewHostKey, &debugSSHExec)
	list.Flags().BoolVarP(&all, "all", "a", false, "show all LIFs, including unreachable entries")
	list.Flags().StringVar(&svm, "svm", "", "SVM name wildcard")
	list.Flags().StringVar(&node, "node", "", "current node name wildcard")
	list.Flags().StringVar(&subnet, "subnet", "", "subnet name wildcard")
	var showKeyFile, showKnownHostsFile string
	var showAcceptNewHostKey, showDebugSSHExec bool
	show := &cobra.Command{Use: "show <lifName>", Args: cobra.ExactArgs(1), Short: "Show all details for a cDOT LIF", RunE: func(command *cobra.Command, arguments []string) error {
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		if host == "" {
			return errors.New("host is required")
		}
		keyPath, err := cdotKeyFile(showKeyFile)
		if err != nil {
			return err
		}
		if showKnownHostsFile == "" {
			showKnownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		var debugWriter io.Writer
		if showDebugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		client, err := openCDOTClient(host, user, keyPath, showKnownHostsFile, showAcceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		output, err := runSSHCommand(client, "network interface show -lif "+shellQuote(arguments[0])+" -instance", debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT LIF %s: %w: %s", arguments[0], err, strings.TrimSpace(string(output)))
		}
		records := parseONTAPInstances(string(output))
		for _, record := range records {
			if instanceField(record, "Logical Interface Name") == arguments[0] {
				return printONTAPRecord(command.OutOrStdout(), record)
			}
		}
		return fmt.Errorf("cDOT LIF %q was not found", arguments[0])
	}}
	addCDOTConnectionFlags(show, &showKeyFile, &showKnownHostsFile, &showAcceptNewHostKey, &showDebugSSHExec)
	group.AddCommand(list, show)
	return group
}

func printONTAPRecord(writer io.Writer, record map[string]string) error {
	fields := make([]string, 0, len(record))
	for field := range record {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{"Field", "Value"})
	for _, field := range fields {
		tableWriter.AppendRow(table.Row{field, record[field]})
	}
	tableWriter.Render()
	return nil
}

func filterLIFsBySVM(records []map[string]string, pattern string) []map[string]string {
	return filterLIFs(records, pattern, "", "")
}

func filterLIFs(records []map[string]string, svm, node, subnet string) []map[string]string {
	filtered := make([]map[string]string, 0, len(records))
	for _, record := range records {
		if svm != "" && !wildcardContains(instanceField(record, "Vserver"), svm) {
			continue
		}
		if node != "" && !wildcardContains(instanceField(record, "Current Node"), node) {
			continue
		}
		if subnet != "" && !wildcardContains(instanceField(record, "Subnet Name"), subnet) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func reachableLIFs(records []map[string]string) []map[string]string {
	filtered := make([]map[string]string, 0, len(records))
	for _, record := range records {
		address := net.ParseIP(instanceField(record, "Network Address"))
		if address == nil || address.To4() == nil || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
			continue
		}
		if status := instanceField(record, "Operational Status"); status != "" && !strings.EqualFold(status, "up") {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

func newCDOTInventoryCommand(name, summary, remoteCommand string, fields []string) *cobra.Command {
	group := &cobra.Command{Use: name, Short: summary}
	var keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec bool
	list := &cobra.Command{Use: "list", Short: summary, RunE: func(command *cobra.Command, _ []string) error {
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		if host == "" {
			return errors.New("host is required")
		}
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		output, err := runSSHCommand(client, remoteCommand, debugWriter)
		if err != nil {
			return fmt.Errorf("query cDOT %s: %w: %s", name, err, strings.TrimSpace(string(output)))
		}
		return printONTAPInventory(command.OutOrStdout(), fields, parseONTAPInstances(string(output)))
	}}
	list.Flags().StringVar(&keyFile, "key", "", "private key path; defaults to the XDG path")
	list.Flags().StringVar(&knownHostsFile, "known-hosts", "", "known_hosts file; defaults to the XDG path")
	list.Flags().BoolVar(&acceptNewHostKey, "accept-new-host-key", false, "trust and save the host key when known_hosts is absent")
	list.Flags().BoolVar(&debugSSHExec, "debug-ssh-exec", false, "print SSH commands and their results to stderr")
	group.AddCommand(list)
	return group
}

func printONTAPInventory(writer io.Writer, fields []string, records []map[string]string) error {
	tableWriter := newTableWriter(writer)
	header := make(table.Row, len(fields))
	for index, field := range fields {
		header[index] = field
	}
	tableWriter.AppendHeader(header)
	for _, record := range records {
		if !hasONTAPInventoryFields(record, fields) {
			continue
		}
		row := make(table.Row, len(fields))
		for index, field := range fields {
			row[index] = instanceField(record, field)
		}
		tableWriter.AppendRow(row)
	}
	tableWriter.Render()
	return nil
}

func hasONTAPInventoryFields(record map[string]string, fields []string) bool {
	for _, field := range fields {
		if instanceField(record, field) != "" {
			return true
		}
	}
	return false
}

func newCDOTListCommand(name, idColumn, summary, remoteCommand, nameField, idField string) *cobra.Command {
	group := &cobra.Command{Use: name, Short: summary}
	var keyFile, knownHostsFile string
	var acceptNewHostKey, debugSSHExec bool
	list := &cobra.Command{Use: "list", Short: summary, RunE: func(command *cobra.Command, _ []string) error {
		host, _ := command.Flags().GetString("host")
		user, _ := command.Flags().GetString("user")
		if host == "" {
			return errors.New("host is required")
		}
		keyPath, err := cdotKeyFile(keyFile)
		if err != nil {
			return err
		}
		if knownHostsFile == "" {
			knownHostsFile, err = cdotKnownHostsFile()
			if err != nil {
				return err
			}
		}
		var debugWriter io.Writer
		if debugSSHExec {
			debugWriter = command.ErrOrStderr()
		}
		client, err := openCDOTClient(host, user, keyPath, knownHostsFile, acceptNewHostKey)
		if err != nil {
			return err
		}
		defer client.Close()
		mappings, err := queryCDOTMappings(client, remoteCommand, nameField, idField, debugWriter)
		if err != nil {
			return err
		}
		return printLiveMappings(command.OutOrStdout(), name, idColumn, mappings)
	}}
	list.Flags().StringVar(&keyFile, "key", "", "private key path; defaults to the XDG path")
	list.Flags().StringVar(&knownHostsFile, "known-hosts", "", "known_hosts file; defaults to the XDG path")
	list.Flags().BoolVar(&acceptNewHostKey, "accept-new-host-key", false, "trust and save the host key when known_hosts is absent")
	list.Flags().BoolVar(&debugSSHExec, "debug-ssh-exec", false, "print SSH commands and their results to stderr")
	group.AddCommand(list)
	return group
}

type cdotMapping struct {
	Name    string
	ID      string
	Vserver string
	FPolicy bool
}

func queryCDOTMappings(client *ssh.Client, command, nameField, idField string, debugWriter io.Writer) ([]cdotMapping, error) {
	output, err := runSSHCommand(client, command, debugWriter)
	if err != nil {
		return nil, fmt.Errorf("query cDOT mappings: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var mappings []cdotMapping
	if strings.HasPrefix(command, "volume show -fields") {
		mappings = parseONTAPVolumeTable(string(output))
	} else {
		for _, record := range parseONTAPInstances(string(output)) {
			name, id := instanceField(record, nameField), instanceField(record, idField)
			if name != "" && id != "" {
				mappings = append(mappings, cdotMapping{Name: name, ID: id, Vserver: instanceField(record, "Vserver")})
			}
		}
	}
	policyOutput, err := runSSHCommand(client, fpolicyPolicyShowCommand+" -instance", debugWriter)
	if err != nil {
		return nil, fmt.Errorf("query cDOT FPolicy policies: %w: %s", err, strings.TrimSpace(string(policyOutput)))
	}
	covered := make(map[string]struct{})
	for _, policy := range parseONTAPInstances(string(policyOutput)) {
		if vserver := instanceField(policy, "Vserver"); vserver != "" {
			covered[vserver] = struct{}{}
		}
	}
	for index := range mappings {
		vserver := mappings[index].Vserver
		if vserver == "" {
			vserver = mappings[index].Name
		}
		if _, found := covered[vserver]; found {
			mappings[index].FPolicy = true
		}
	}
	return mappings, nil
}

func parseONTAPVolumeTable(output string) []cdotMapping {
	var mappings []cdotMapping
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] == "vserver" || fields[2] == "-" {
			continue
		}
		if _, err := strconv.ParseUint(fields[2], 10, 64); err != nil {
			continue
		}
		mappings = append(mappings, cdotMapping{Vserver: fields[0], Name: fields[1], ID: fields[2]})
	}
	return mappings
}

func instanceField(record map[string]string, field string) string {
	if value := record[field]; value != "" {
		return value
	}
	if strings.EqualFold(field, "Vserver") {
		if value := record["Vserver Name"]; value != "" {
			return value
		}
	}
	for name, value := range record {
		if strings.EqualFold(name, field) {
			return value
		}
	}
	return ""
}

func parseONTAPInstances(output string) []map[string]string {
	var records []map[string]string
	current := map[string]string{}
	lastField := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(current) > 0 {
				records = append(records, current)
				current = map[string]string{}
				lastField = ""
			}
			continue
		}
		field, value, found := strings.Cut(trimmed, ":")
		if found && strings.TrimSpace(field) != "" {
			current[strings.TrimSpace(field)] = strings.TrimSpace(value)
			lastField = strings.TrimSpace(field)
			continue
		}
		if lastField != "" && len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			current[lastField] = strings.TrimSpace(current[lastField] + " " + trimmed)
		}
	}
	if len(current) > 0 {
		records = append(records, current)
	}
	return records
}

func printLiveMappings(writer io.Writer, nameColumn, idColumn string, mappings []cdotMapping) error {
	sort.Slice(mappings, func(left, right int) bool { return mappings[left].Name < mappings[right].Name })
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{nameColumn, idColumn, "FPolicy"})
	for _, mapping := range mappings {
		covered := "no"
		if mapping.FPolicy {
			covered = "yes"
		}
		tableWriter.AppendRow(table.Row{mapping.Name, mapping.ID, covered})
	}
	tableWriter.Render()
	return nil
}

func printMappings(writer io.Writer, nameColumn, idColumn string, mappings []store.Mapping) error {
	tableWriter := newTableWriter(writer)
	tableWriter.AppendHeader(table.Row{nameColumn, idColumn})
	for _, mapping := range mappings {
		tableWriter.AppendRow(table.Row{mapping.Name, mapping.ID})
	}
	tableWriter.Render()
	return nil
}

func newServiceCommand() *cobra.Command {
	service := &cobra.Command{Use: "service", Short: "Manage the pathdiff systemd service"}
	service.AddCommand(newServiceStartCommand(), newServiceRestartCommand(), newServiceStatusCommand(), newServiceRefreshCommand(), newServiceListPortsCommand(), newServiceStopCommand(), newServiceMonitorCommand())
	return service
}

func newServiceListPortsCommand() *cobra.Command {
	var controlPath string
	command := &cobra.Command{Use: "list-ports", Short: "List active FPolicy listener ports", RunE: func(command *cobra.Command, _ []string) error {
		response, err := callControl(controlPath, controlRequest{Command: "listener-ports"})
		if err != nil {
			return err
		}
		tableWriter := newTableWriter(command.OutOrStdout())
		tableWriter.AppendHeader(table.Row{"Port", "SVM", "Allowed LIF IPv4s"})
		for _, port := range response.ListenerPorts {
			tableWriter.AppendRow(table.Row{port.Port, strings.Join(port.SVMs, ", "), strings.Join(port.Sources, ", ")})
		}
		tableWriter.Render()
		return nil
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	return command
}

func newServiceRestartCommand() *cobra.Command {
	return &cobra.Command{Use: "restart", Short: "Restart the user systemd service", RunE: func(*cobra.Command, []string) error {
		return runSystemctlUser("restart", "pathdiff.service")
	}}
}

func newServiceRefreshCommand() *cobra.Command {
	var controlPath string
	command := &cobra.Command{Use: "refresh", Short: "Refresh cDOT FPolicy senders and listeners", RunE: func(command *cobra.Command, _ []string) error {
		response, err := callControl(controlPath, controlRequest{Command: "fpolicy-refresh"})
		if err != nil {
			return err
		}
		return printResponse(response)
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	return command
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
		connections, ports, events, rate := "-", "-", "-", "-"
		if state == "active" {
			response, err := callControl(controlPath, controlRequest{Command: "status"})
			if err == nil {
				connections = formatHealthCount(response.Connections)
				ports = formatHealthCount(len(response.ListenerPorts))
				events = formatCount(response.EventCount)
				rate = fmt.Sprintf("%.2f", response.RequestRate)
			} else {
				state += " (control unavailable)"
			}
		}
		tableWriter := newTableWriter(command.OutOrStdout())
		tableWriter.AppendHeader(table.Row{"Service", "State", "FPolicy Connections", "Listen Ports", "Registered Events", "Requests/s Since Start"})
		tableWriter.AppendRow(table.Row{"pathdiff", state, connections, ports, events, rate})
		tableWriter.Render()
		return nil
	}}
	command.Flags().StringVar(&controlPath, "control", defaultControl, "Unix control socket")
	return command
}

func formatHealthCount(value int) string {
	formatted := formatCount(uint64(value))
	if value == 0 {
		return text.FgRed.Sprint(formatted)
	}
	return formatted
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
	unitPath, err := systemdUserUnitPath()
	if err != nil {
		return "", false, err
	}
	if _, err := os.Stat(unitPath); err == nil {
		if listenAddr == defaultListen {
			unit, readErr := os.ReadFile(unitPath)
			if readErr != nil {
				return "", false, readErr
			}
			if strings.Contains(string(unit), "--listen "+shellQuote(":9911")) {
				updated := strings.Replace(string(unit), "--listen "+shellQuote(":9911"), "--listen "+shellQuote(defaultListen), 1)
				if err := os.WriteFile(unitPath, []byte(updated), 0o644); err != nil {
					return "", false, err
				}
				return unitPath, true, nil
			}
		}
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

func systemdUserUnitPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user", "pathdiff.service"), nil
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

func formatEventCount(value uint64) string {
	if value < 1000 {
		return strconv.FormatUint(value, 10)
	}
	units := []string{"", "k", "M", "G", "T"}
	amount := float64(value)
	unit := 0
	for amount >= 1000 && unit < len(units)-1 {
		amount /= 1000
		unit++
	}
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.1f", amount), "0"), ".") + units[unit]
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
	tableWriter.SetColumnConfigs([]table.ColumnConfig{{Name: "Port", Align: text.AlignRight, AlignHeader: text.AlignRight}})
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
	var showNode, showLIF, showOperation, hideTimestamp, hideSVM, hideVolume, jsonOutput bool
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
		volumes, err := queryMonitorVolumes()
		if err != nil {
			return err
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		type eventKey struct {
			path, operation string
			timestamp       time.Time
		}
		seen := make(map[eventKey]struct{})
		for {
			response, err := callControl(controlPath, controlRequest{Command: "recent", Since: since})
			if err != nil {
				return err
			}
			var events []store.Event
			for _, event := range response.Events {
				if path != "" && !strings.HasPrefix(event.Path, path) {
					continue
				}
				key := eventKey{path: event.Path, operation: event.Operation, timestamp: event.Timestamp.UTC()}
				if event.Timestamp.After(since) {
					since = event.Timestamp
					clear(seen)
				}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				resolveMonitorEvent(&event, volumes)
				events = append(events, event)
			}
			if len(events) > 0 {
				if jsonOutput {
					for _, event := range events {
						if err := json.NewEncoder(command.OutOrStdout()).Encode(event); err != nil {
							return err
						}
					}
				} else {
					if err := printMonitorEvents(command.OutOrStdout(), newestMonitorEventsByPath(events), monitorOptions{ShowNode: showNode, ShowLIF: showLIF, ShowOperation: showOperation, HideTimestamp: hideTimestamp, HideSVM: hideSVM, HideVolume: hideVolume}); err != nil {
						return err
					}
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
	command.Flags().BoolVar(&showNode, "show-node", false, "include the ONTAP node ID")
	command.Flags().BoolVar(&showLIF, "show-lif", false, "include the sender LIF IPv4")
	command.Flags().BoolVar(&showOperation, "show-op", false, "include the operation column")
	command.Flags().BoolVar(&hideTimestamp, "hide-timestamp", false, "hide the timestamp column")
	command.Flags().BoolVar(&hideSVM, "hide-svm", false, "hide the SVM column")
	command.Flags().BoolVar(&hideVolume, "hide-volume", false, "hide the volume column")
	command.Flags().BoolVar(&jsonOutput, "json", false, "output resolved events as JSON lines")
	return command
}

type monitorVolume struct {
	Name string
	SVM  string
}

func queryMonitorVolumes() (map[string]monitorVolume, error) {
	host := defaultCDOTCluster()
	if host == "" {
		return nil, errors.New("cDOT host is required to resolve monitor volume and SVM names")
	}
	keyFile, err := cdotKeyFile("")
	if err != nil {
		return nil, err
	}
	knownHostsFile, err := cdotKnownHostsFile()
	if err != nil {
		return nil, err
	}
	client, err := openCDOTClient(host, "pathdiff", keyFile, knownHostsFile, false)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	output, err := runSSHCommand(client, "volume show -fields vserver,volume,msid", nil)
	if err != nil {
		return nil, fmt.Errorf("query cDOT volumes for monitor: %w: %s", err, strings.TrimSpace(string(output)))
	}
	volumes := make(map[string]monitorVolume)
	for _, mapping := range parseONTAPVolumeTable(string(output)) {
		volumes[mapping.ID] = monitorVolume{Name: mapping.Name, SVM: mapping.Vserver}
	}
	return volumes, nil
}

func resolveMonitorEvent(event *store.Event, volumes map[string]monitorVolume) {
	volume, found := volumes[event.VolumeMSID]
	if !found {
		return
	}
	if event.VolumeName == "" {
		event.VolumeName = volume.Name
	}
	if event.SVMName == "" {
		event.SVMName = volume.SVM
	}
}

type monitorOptions struct {
	ShowNode, ShowLIF, ShowOperation   bool
	HideTimestamp, HideSVM, HideVolume bool
}

func newestMonitorEventsByPath(events []store.Event) []store.Event {
	newest := make(map[string]store.Event)
	for _, event := range events {
		if current, found := newest[event.Path]; !found || event.Timestamp.After(current.Timestamp) {
			newest[event.Path] = event
		}
	}
	grouped := make([]store.Event, 0, len(newest))
	for _, event := range newest {
		grouped = append(grouped, event)
	}
	sort.Slice(grouped, func(left, right int) bool { return grouped[left].Timestamp.Before(grouped[right].Timestamp) })
	return grouped
}

func printMonitorEvents(writer io.Writer, events []store.Event, options monitorOptions) error {
	tableWriter := newTableWriter(writer)
	header := table.Row{}
	if !options.HideTimestamp {
		header = append(header, "Timestamp")
	}
	if options.ShowOperation {
		header = append(header, "Operation")
	}
	if !options.HideSVM {
		header = append(header, "SVM")
	}
	if !options.HideVolume {
		header = append(header, "Volume")
	}
	if options.ShowNode {
		header = append(header, "Node")
	}
	if options.ShowLIF {
		header = append(header, "LIF")
	}
	header = append(header, "Path")
	tableWriter.AppendHeader(header)
	for _, event := range events {
		row := table.Row{}
		if !options.HideTimestamp {
			row = append(row, event.Timestamp.UTC().Format(time.RFC3339Nano))
		}
		if options.ShowOperation {
			row = append(row, event.Operation)
		}
		if !options.HideSVM {
			row = append(row, eventSVM(event))
		}
		if !options.HideVolume {
			row = append(row, eventVolume(event))
		}
		if options.ShowNode {
			row = append(row, event.NodeID)
		}
		if options.ShowLIF {
			row = append(row, event.LIFIPv4)
		}
		row = append(row, event.Path)
		tableWriter.AppendRow(row)
	}
	tableWriter.Render()
	return nil
}

func eventSVM(event store.Event) string {
	if event.SVMName != "" {
		return event.SVMName
	}
	return event.SVMID
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
