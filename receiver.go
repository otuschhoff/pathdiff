package pathdiff

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otuschhoff/pathdiff/internal/fpolicy"
	"github.com/otuschhoff/pathdiff/internal/store"
)

// Config configures an embeddable Receiver.
type Config struct {
	// DatabasePath is opened and owned by the receiver when Database is nil.
	DatabasePath string
	// Database may be supplied by the embedding application. It remains caller-owned.
	Database *Database
	// Listeners are opened when Start is called.
	Listeners []ListenerConfig
	// ControlPath enables the JSON control socket when non-empty.
	ControlPath string
	// RecordDirectory stores raw per-connection traffic when non-empty.
	RecordDirectory string
	// Logger receives operational diagnostics. The standard logger is used when nil.
	Logger *log.Logger
	// Refresh is invoked by Refresh and optionally at RefreshInterval.
	Refresh func(context.Context, *Receiver) error
	// RefreshInterval periodically invokes Refresh when both fields are configured.
	RefreshInterval time.Duration
	// RetentionInterval periodically applies the persisted retention policy.
	RetentionInterval time.Duration
	// RestoreListeners opens the last persisted endpoints at Start so the receiver
	// accepts senders before discovery completes.
	RestoreListeners bool
}

// ListenerConfig describes one receiver endpoint and its accepted sources.
type ListenerConfig = store.ListenerConfig

// ListenerInfo describes a running receiver endpoint.
type ListenerInfo struct {
	Address string   `json:"address"`
	Port    int      `json:"port"`
	SVMs    []string `json:"svms,omitempty"`
	Sources []string `json:"sources,omitempty"`
}

// EngineInfo describes an active FPolicy sender.
type EngineInfo struct {
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

// Status describes a receiver's current state.
type Status struct {
	Running     bool           `json:"running"`
	Connections int            `json:"connections"`
	EventCount  uint64         `json:"event_count"`
	RequestRate float64        `json:"request_rate"`
	Listeners   []ListenerInfo `json:"listeners,omitempty"`
}

type receiverListener struct {
	config   ListenerConfig
	listener net.Listener
}

type senderState struct {
	active         int
	totalEvents    uint64
	connectedSince time.Time
	localPort      string
	nodeID         string
	svmID          string
	lastSeen       time.Time
}

// Receiver accepts FPolicy streams and stores events in a pathdiff Database.
type Receiver struct {
	config Config
	db     *Database
	ownsDB bool

	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	started     bool
	closed      bool
	listeners   map[string]*receiverListener
	control     net.Listener
	connections map[net.Conn]struct{}
	senders     map[string]*senderState
	startedAt   time.Time
	totalEvents uint64
	workers     sync.WaitGroup
	done        chan struct{}
	closeErr    error
	captureSeq  atomic.Uint64
}

// NewReceiver constructs a receiver. Network listeners are opened by Start.
func NewReceiver(config Config) (*Receiver, error) {
	if config.Database != nil && config.DatabasePath != "" {
		return nil, errors.New("Database and DatabasePath are mutually exclusive")
	}
	database := config.Database
	ownsDatabase := false
	if database == nil {
		if config.DatabasePath == "" {
			return nil, errors.New("Database or DatabasePath is required")
		}
		var err error
		database, err = OpenDatabase(config.DatabasePath)
		if err != nil {
			return nil, fmt.Errorf("open receiver database: %w", err)
		}
		ownsDatabase = true
	}
	if config.RetentionInterval == 0 {
		config.RetentionInterval = time.Minute
	}
	return &Receiver{
		config:      config,
		db:          database,
		ownsDB:      ownsDatabase,
		listeners:   make(map[string]*receiverListener),
		connections: make(map[net.Conn]struct{}),
		senders:     make(map[string]*senderState),
		done:        make(chan struct{}),
	}, nil
}

// Database returns the receiver's database for direct in-process queries.
func (r *Receiver) Database() *Database { return r.db }

// SetRefresh configures application-owned listener discovery before Start.
func (r *Receiver) SetRefresh(refresh func(context.Context, *Receiver) error, interval time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.closed {
		return errors.New("receiver refresh cannot be changed after start")
	}
	r.config.Refresh = refresh
	r.config.RefreshInterval = interval
	return nil
}

// Start opens configured listeners and starts background work.
func (r *Receiver) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("receiver context is required")
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return errors.New("receiver is already started")
	}
	if r.closed {
		r.mu.Unlock()
		return errors.New("receiver is closed")
	}
	r.ctx, r.cancel = context.WithCancel(ctx)
	r.started = true
	r.startedAt = time.Now().UTC()
	r.mu.Unlock()

	if err := r.SetListeners(r.startupListeners()); err != nil {
		r.cancel()
		r.shutdown()
		return err
	}
	if r.config.ControlPath != "" {
		if err := r.startControl(); err != nil {
			r.cancel()
			r.shutdown()
			return err
		}
	}
	if r.config.Refresh != nil {
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			if err := r.Refresh(); err != nil && !errors.Is(err, context.Canceled) {
				r.logf("initial receiver refresh: %v", err)
			}
		}()
	}
	go func() {
		<-r.ctx.Done()
		r.shutdown()
	}()
	if r.config.Refresh != nil && r.config.RefreshInterval > 0 {
		r.workers.Add(1)
		go r.refreshEvery()
	}
	if r.config.RetentionInterval > 0 {
		r.workers.Add(1)
		go r.retainEvery()
	}
	return nil
}

// Run starts the receiver and blocks until ctx is canceled or Close is called.
func (r *Receiver) Run(ctx context.Context) error {
	if err := r.Start(ctx); err != nil {
		return err
	}
	return r.Wait()
}

// Wait blocks until the receiver has shut down.
func (r *Receiver) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeErr
}

// Close gracefully stops listeners and active connections.
func (r *Receiver) Close() error {
	r.mu.Lock()
	cancel := r.cancel
	started := r.started
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return r.Wait()
	}
	if !started {
		r.shutdown()
		return r.Wait()
	}
	cancel()
	return r.Wait()
}

// Refresh invokes the application-supplied listener discovery callback.
func (r *Receiver) Refresh() error {
	if r.config.Refresh == nil {
		return nil
	}
	r.mu.Lock()
	ctx := r.ctx
	r.mu.Unlock()
	if ctx == nil {
		return errors.New("receiver is not started")
	}
	return r.config.Refresh(ctx, r)
}

// SetListeners atomically reconciles the running listener set.
func (r *Receiver) SetListeners(configs []ListenerConfig) error {
	if err := r.setListeners(configs); err != nil {
		return err
	}
	if err := r.db.SetListenerSnapshot(store.ListenerSnapshot{UpdatedAt: time.Now().UTC(), Listeners: r.listenerConfigs()}); err != nil {
		r.logf("persist listener configuration: %v", err)
	}
	return nil
}

// startupListeners prefers explicit configuration and otherwise reuses the last persisted endpoints.
func (r *Receiver) startupListeners() []ListenerConfig {
	if len(r.config.Listeners) > 0 || !r.config.RestoreListeners {
		return r.config.Listeners
	}
	snapshot, err := r.db.ListenerSnapshot()
	if err != nil {
		r.logf("restore persisted listener configuration: %v", err)
		return nil
	}
	if len(snapshot.Listeners) > 0 {
		r.logf("restored %d persisted listeners discovered at %s", len(snapshot.Listeners), snapshot.UpdatedAt.Format(time.RFC3339))
	}
	return snapshot.Listeners
}

func (r *Receiver) listenerConfigs() []ListenerConfig {
	r.mu.Lock()
	defer r.mu.Unlock()
	configs := make([]ListenerConfig, 0, len(r.listeners))
	for _, current := range r.listeners {
		configs = append(configs, current.config)
	}
	sort.Slice(configs, func(left, right int) bool { return configs[left].Address < configs[right].Address })
	return configs
}

func (r *Receiver) setListeners(configs []ListenerConfig) error {
	validated := make(map[string]ListenerConfig, len(configs))
	for _, config := range configs {
		if config.Address == "" {
			return errors.New("listener address is required")
		}
		if _, exists := validated[config.Address]; exists {
			return fmt.Errorf("duplicate listener address %q", config.Address)
		}
		validated[config.Address] = copyListenerConfig(config)
	}

	r.mu.Lock()
	if !r.started || r.closed {
		r.mu.Unlock()
		return errors.New("receiver is not running")
	}
	existing := make(map[string]*receiverListener, len(r.listeners))
	for address, listener := range r.listeners {
		existing[address] = listener
	}
	r.mu.Unlock()

	opened := make(map[string]*receiverListener)
	for address, config := range validated {
		if existing[address] != nil {
			continue
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			closeReceiverListeners(opened)
			return fmt.Errorf("listen for FPolicy events on %s: %w", address, err)
		}
		opened[address] = &receiverListener{config: config, listener: listener}
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		closeReceiverListeners(opened)
		return errors.New("receiver is closed")
	}
	for address, current := range r.listeners {
		config, wanted := validated[address]
		if !wanted {
			_ = current.listener.Close()
			delete(r.listeners, address)
			continue
		}
		current.config = config
	}
	for address, listener := range opened {
		r.listeners[address] = listener
		r.workers.Add(1)
		go r.accept(listener)
	}
	r.mu.Unlock()
	return nil
}

// Listeners returns a stable snapshot of active endpoints.
func (r *Receiver) Listeners() []ListenerInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	listeners := make([]ListenerInfo, 0, len(r.listeners))
	for _, current := range r.listeners {
		_, portText, _ := net.SplitHostPort(current.listener.Addr().String())
		port := 0
		_, _ = fmt.Sscanf(portText, "%d", &port)
		listeners = append(listeners, ListenerInfo{
			Address: current.listener.Addr().String(),
			Port:    port,
			SVMs:    append([]string(nil), current.config.SVMs...),
			Sources: append([]string(nil), current.config.AllowedSources...),
		})
	}
	sort.Slice(listeners, func(left, right int) bool { return listeners[left].Address < listeners[right].Address })
	return listeners
}

// Status returns current receiver and persistence metrics.
func (r *Receiver) Status() (Status, error) {
	count, err := r.db.EventCount()
	if err != nil {
		return Status{}, err
	}
	r.mu.Lock()
	connections := 0
	for _, sender := range r.senders {
		connections += sender.active
	}
	elapsed := time.Since(r.startedAt).Seconds()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(r.totalEvents) / elapsed
	}
	running := r.started && !r.closed
	r.mu.Unlock()
	return Status{Running: running, Connections: connections, EventCount: count, RequestRate: rate, Listeners: r.Listeners()}, nil
}

// Engines returns active sender metrics.
func (r *Receiver) Engines() []EngineInfo {
	r.mu.Lock()
	now := time.Now().UTC()
	engines := make([]EngineInfo, 0, len(r.senders))
	for address, sender := range r.senders {
		if sender.active == 0 {
			continue
		}
		elapsed := now.Sub(sender.connectedSince).Seconds()
		rate := 0.0
		if elapsed > 0 {
			rate = float64(sender.totalEvents) / elapsed
		}
		engines = append(engines, EngineInfo{Since: sender.connectedSince, TotalEvents: sender.totalEvents, AverageRate: rate, LIFIPv4: address, NodeID: sender.nodeID, SVMID: sender.svmID, LocalPort: sender.localPort, LastSeen: sender.lastSeen})
	}
	r.mu.Unlock()
	for index := range engines {
		stored, err := r.db.Sender(engines[index].LIFIPv4)
		if err != nil {
			r.logf("read persisted sender %s: %v", engines[index].LIFIPv4, err)
			continue
		}
		engines[index].SVMName = stored.SVMName
		engines[index].NodeName = stored.NodeName
		if engines[index].SVMID == "" {
			engines[index].SVMID = stored.SVMID
		}
		if engines[index].NodeID == "" {
			engines[index].NodeID = stored.NodeID
		}
	}
	return engines
}

func (r *Receiver) accept(current *receiverListener) {
	defer r.workers.Done()
	for {
		connection, err := current.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || r.contextDone() {
				return
			}
			r.logf("accept FPolicy connection on %s: %v", current.listener.Addr(), err)
			continue
		}
		sender := remoteHost(connection.RemoteAddr())
		r.mu.Lock()
		allowed := sourceAllowed(current.config.AllowedSources, sender)
		r.mu.Unlock()
		if !allowed {
			r.logf("reject unexpected FPolicy sender %s on %s", connection.RemoteAddr(), connection.LocalAddr())
			_ = connection.Close()
			continue
		}
		r.mu.Lock()
		r.connections[connection] = struct{}{}
		state := r.sender(sender)
		if state.active == 0 {
			state.connectedSince = time.Now().UTC()
			_, state.localPort, _ = net.SplitHostPort(connection.LocalAddr().String())
			state.totalEvents = 0
			state.lastSeen = time.Time{}
		}
		state.active++
		r.mu.Unlock()
		r.persistSender(sender)
		r.workers.Add(1)
		go r.readConnection(connection, sender)
	}
}

func (r *Receiver) readConnection(connection net.Conn, sender string) {
	defer r.workers.Done()
	active := connection
	if r.config.RecordDirectory != "" {
		recorder, err := r.newTrafficRecorder(connection)
		if err != nil {
			r.logf("create traffic capture for %s: %v", sender, err)
			_ = connection.Close()
			r.disconnected(connection, sender)
			return
		}
		active = recorder
	}
	defer func() {
		if err := active.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			r.logf("close event connection from %s: %v", sender, err)
		}
		r.disconnected(connection, sender)
	}()
	r.readEvents(active, sender)
}

func (r *Receiver) readEvents(connection net.Conn, sender string) {
	reader := bufio.NewReader(connection)
	first, err := reader.Peek(1)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			r.logf("read event stream from %s: %v", sender, err)
		}
		return
	}
	switch first[0] {
	case '<':
		r.readRawXML(reader, sender)
	case 0x22:
		r.readONTAPXML(reader, connection, sender)
	case '{':
		r.readJSONLines(reader, sender)
	default:
		r.logf("reject event connection from %s: unsupported protocol prefix %#x", sender, first[0])
	}
}

func (r *Receiver) readJSONLines(reader io.Reader, sender string) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			r.logf("decode JSON event from %s: %v", sender, err)
			continue
		}
		if event.Path == "" {
			r.logf("reject event from %s: path is required", sender)
			continue
		}
		if !r.storeEvent(sender, event) {
			return
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		r.logf("read JSON event stream from %s: %v", sender, err)
	}
}

func (r *Receiver) readRawXML(reader io.Reader, sender string) {
	decoder := xml.NewDecoder(reader)
	for {
		event, err := fpolicy.DecodeXMLNotification(decoder)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			r.logf("read XML event from %s: %v", sender, err)
			return
		}
		if !r.storeEvent(sender, event) {
			return
		}
	}
}

func (r *Receiver) readONTAPXML(reader io.Reader, connection net.Conn, sender string) {
	message, err := fpolicy.ReadONTAPXMLFrame(reader)
	if err != nil {
		r.logf("read ONTAP handshake from %s: %v", sender, err)
		return
	}
	if message.Type != "NEGO_REQ" {
		r.logf("reject ONTAP session from %s: expected NEGO_REQ, got %s", sender, message.Type)
		return
	}
	response, err := fpolicy.ONTAPNegotiateResponse(message.Session, message.VserverUUID, message.PolicyName)
	if err != nil {
		r.logf("encode ONTAP handshake response for %s: %v", sender, err)
		return
	}
	if err := fpolicy.WriteONTAPXMLFrame(connection, "NEGO_RESP", response); err != nil {
		r.logf("write ONTAP handshake response to %s: %v", sender, err)
		return
	}
	r.mu.Lock()
	state := r.sender(sender)
	state.nodeID = message.NodeID
	state.svmID = message.VserverUUID
	r.mu.Unlock()
	r.persistSender(sender)
	for {
		message, err := fpolicy.ReadONTAPXMLFrame(reader)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			r.logf("read ONTAP event from %s: %v", sender, err)
			return
		}
		if message.Type == "KEEP_ALIVE" {
			continue
		}
		var event Event
		switch message.Type {
		case "SCREEN_REQ":
			event, err = fpolicy.ParseScreenRequest(message.Payload)
		case "NOTIFY_REQ":
			event, err = fpolicy.ParseXMLNotification(message.Payload)
		default:
			continue
		}
		if err != nil {
			r.logf("decode ONTAP %s from %s: %v", message.Type, sender, err)
			continue
		}
		if !r.storeEvent(sender, event) {
			return
		}
	}
}

func (r *Receiver) storeEvent(sender string, event Event) bool {
	r.mu.Lock()
	state := r.sender(sender)
	event.SVMID = state.svmID
	event.NodeID = state.nodeID
	r.mu.Unlock()
	event.LIFIPv4 = sender
	if err := r.db.Store(event); err != nil {
		r.logf("store event from %s; closing sender connection: %v", sender, err)
		return false
	}
	r.mu.Lock()
	state = r.sender(sender)
	state.totalEvents++
	state.lastSeen = time.Now().UTC()
	r.totalEvents++
	r.mu.Unlock()
	return true
}

func (r *Receiver) disconnected(connection net.Conn, sender string) {
	r.mu.Lock()
	delete(r.connections, connection)
	record := store.Sender{LIFIPv4: sender}
	if state := r.senders[sender]; state != nil {
		state.active--
		if state.active <= 0 {
			delete(r.senders, sender)
		}
		record = senderRecord(sender, state)
	}
	r.mu.Unlock()
	r.persistSenderRecord(record)
}

func (r *Receiver) persistSender(address string) {
	r.mu.Lock()
	record := senderRecord(address, r.senders[address])
	r.mu.Unlock()
	r.persistSenderRecord(record)
}

func senderRecord(address string, state *senderState) store.Sender {
	record := store.Sender{LIFIPv4: address, UpdatedAt: time.Now().UTC()}
	if state == nil {
		return record
	}
	record.Connected = state.active > 0
	record.SVMID = state.svmID
	record.NodeID = state.nodeID
	record.LocalPort = state.localPort
	record.FirstSeen = state.connectedSince
	record.LastSeen = state.lastSeen
	record.TotalEvents = state.totalEvents
	return record
}

// persistSenderRecord keeps the last known sender session queryable after restarts,
// retaining the cDOT names that only configuration verification can supply.
func (r *Receiver) persistSenderRecord(sender store.Sender) {
	if sender.LIFIPv4 == "" {
		return
	}
	if sender.UpdatedAt.IsZero() {
		sender.UpdatedAt = time.Now().UTC()
	}
	stored, err := r.db.Sender(sender.LIFIPv4)
	if err != nil {
		r.logf("read persisted sender %s: %v", sender.LIFIPv4, err)
		stored = store.Sender{}
	}
	sender.LIFName = stored.LIFName
	sender.SVMName = stored.SVMName
	sender.NodeName = stored.NodeName
	if sender.SVMID == "" {
		sender.SVMID = stored.SVMID
	}
	if sender.NodeID == "" {
		sender.NodeID = stored.NodeID
	}
	if sender.LocalPort == "" {
		sender.LocalPort = stored.LocalPort
	}
	if sender.FirstSeen.IsZero() {
		sender.FirstSeen = stored.FirstSeen
	}
	if err := r.db.SetSender(sender); err != nil {
		r.logf("persist sender %s: %v", sender.LIFIPv4, err)
	}
}

func (r *Receiver) persistSenders() {
	r.mu.Lock()
	addresses := make([]string, 0, len(r.senders))
	for address := range r.senders {
		addresses = append(addresses, address)
	}
	r.mu.Unlock()
	for _, address := range addresses {
		r.persistSender(address)
	}
}

func (r *Receiver) sender(address string) *senderState {
	state := r.senders[address]
	if state == nil {
		state = &senderState{}
		r.senders[address] = state
	}
	return state
}

func (r *Receiver) refreshEvery() {
	defer r.workers.Done()
	ticker := time.NewTicker(r.config.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if err := r.Refresh(); err != nil && !errors.Is(err, context.Canceled) {
				r.logf("refresh receiver listeners: %v", err)
			}
		}
	}
}

func (r *Receiver) retainEvery() {
	defer r.workers.Done()
	apply := func() {
		if _, err := r.db.ApplyRetention(time.Now().UTC()); err != nil {
			r.logf("apply event retention: %v", err)
		}
		r.persistSenders()
	}
	apply()
	ticker := time.NewTicker(r.config.RetentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			apply()
		}
	}
}

func (r *Receiver) shutdown() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	listeners := r.listeners
	r.listeners = make(map[string]*receiverListener)
	control := r.control
	r.control = nil
	connections := make([]net.Conn, 0, len(r.connections))
	for connection := range r.connections {
		connections = append(connections, connection)
	}
	r.mu.Unlock()
	closeReceiverListeners(listeners)
	if control != nil {
		_ = control.Close()
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	r.workers.Wait()
	r.persistSenders()
	if r.config.ControlPath != "" {
		if err := os.Remove(r.config.ControlPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			r.mu.Lock()
			r.closeErr = errors.Join(r.closeErr, fmt.Errorf("remove control socket: %w", err))
			r.mu.Unlock()
		}
	}
	if r.ownsDB {
		if err := r.db.Close(); err != nil {
			r.mu.Lock()
			r.closeErr = errors.Join(r.closeErr, fmt.Errorf("close receiver database: %w", err))
			r.mu.Unlock()
		}
	}
	close(r.done)
}

func (r *Receiver) contextDone() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ctx != nil && r.ctx.Err() != nil
}

func (r *Receiver) logf(format string, arguments ...any) {
	if r.config.Logger != nil {
		r.config.Logger.Printf(format, arguments...)
		return
	}
	log.Printf(format, arguments...)
}

func copyListenerConfig(config ListenerConfig) ListenerConfig {
	config.AllowedSources = append([]string(nil), config.AllowedSources...)
	config.SVMs = append([]string(nil), config.SVMs...)
	sort.Strings(config.AllowedSources)
	sort.Strings(config.SVMs)
	return config
}

func sourceAllowed(sources []string, source string) bool {
	if len(sources) == 0 {
		return true
	}
	index := sort.SearchStrings(sources, source)
	return index < len(sources) && sources[index] == source
}

func remoteHost(address net.Addr) string {
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
}

func closeReceiverListeners(listeners map[string]*receiverListener) {
	for _, listener := range listeners {
		_ = listener.listener.Close()
	}
}

type trafficRecorder struct {
	net.Conn
	in  *os.File
	out *os.File
}

func (r *Receiver) newTrafficRecorder(connection net.Conn) (*trafficRecorder, error) {
	if err := os.MkdirAll(r.config.RecordDirectory, 0o700); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("%s-%06d", time.Now().UTC().Format("20060102T150405.000000000Z"), r.captureSeq.Add(1))
	in, err := os.Create(filepath.Join(r.config.RecordDirectory, prefix+".in"))
	if err != nil {
		return nil, err
	}
	out, err := os.Create(filepath.Join(r.config.RecordDirectory, prefix+".out"))
	if err != nil {
		return nil, errors.Join(err, in.Close())
	}
	return &trafficRecorder{Conn: connection, in: in, out: out}, nil
}

func (r *trafficRecorder) Read(payload []byte) (int, error) {
	count, err := r.Conn.Read(payload)
	if count > 0 {
		_, err = r.in.Write(payload[:count])
	}
	return count, err
}

func (r *trafficRecorder) Write(payload []byte) (int, error) {
	count, err := r.Conn.Write(payload)
	if count > 0 {
		_, err = r.out.Write(payload[:count])
	}
	return count, err
}

func (r *trafficRecorder) Close() error {
	return errors.Join(r.in.Close(), r.out.Close(), r.Conn.Close())
}
