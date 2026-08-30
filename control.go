package pathdiff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Request is the stable control-socket request envelope.
type Request struct {
	Command    string          `json:"command"`
	Search     string          `json:"search,omitempty"`
	Parents    []ParentSummary `json:"parents,omitempty"`
	Since      time.Time       `json:"since,omitempty"`
	Path       string          `json:"path,omitempty"`
	Start      time.Time       `json:"start,omitempty"`
	End        time.Time       `json:"end,omitempty"`
	VolumeMSID string          `json:"volume_msid,omitempty"`
	VolumeName string          `json:"volume_name,omitempty"`
	SVMID      string          `json:"svm_id,omitempty"`
	SVMName    string          `json:"svm_name,omitempty"`
	Retention  time.Duration   `json:"retention,omitempty"`
}

// Response is the stable control-socket response envelope.
type Response struct {
	Error         string          `json:"error,omitempty"`
	Status        string          `json:"status,omitempty"`
	Connections   int             `json:"connections,omitempty"`
	EventCount    uint64          `json:"event_count,omitempty"`
	RequestRate   float64         `json:"request_rate,omitempty"`
	DBPath        string          `json:"db_path,omitempty"`
	DBSize        uint64          `json:"db_size,omitempty"`
	Events        []Event         `json:"events,omitempty"`
	Parents       []ParentSummary `json:"parents,omitempty"`
	Engines       []EngineInfo    `json:"engines,omitempty"`
	Mappings      []Mapping       `json:"mappings,omitempty"`
	ListenerPorts []ListenerInfo  `json:"listener_ports,omitempty"`
	Retention     time.Duration   `json:"retention,omitempty"`
	DeletedEvents uint64          `json:"deleted_events,omitempty"`
}

// Client queries a Receiver running in another process.
type Client struct {
	ControlPath string
	Dialer      net.Dialer
}

// NewClient constructs a control-socket client.
func NewClient(controlPath string) *Client {
	return &Client{ControlPath: controlPath}
}

// Do sends one request and returns its response.
func (c *Client) Do(ctx context.Context, request Request) (Response, error) {
	if c.ControlPath == "" {
		return Response{}, errors.New("control socket path is required")
	}
	connection, err := c.Dialer.DialContext(ctx, "unix", c.ControlPath)
	if err != nil {
		return Response{}, fmt.Errorf("connect to pathdiff receiver: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return Response{}, fmt.Errorf("set control deadline: %w", err)
		}
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return Response{}, fmt.Errorf("send receiver command %q: %w", request.Command, err)
	}
	var response Response
	if err := json.NewDecoder(connection).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("read receiver command %q response: %w", request.Command, err)
	}
	if response.Error != "" {
		return Response{}, fmt.Errorf("receiver command %q: %s", request.Command, response.Error)
	}
	return response, nil
}

// Status returns remote receiver metrics.
func (c *Client) Status(ctx context.Context) (Status, error) {
	response, err := c.Do(ctx, Request{Command: "status"})
	if err != nil {
		return Status{}, err
	}
	return Status{Running: response.Status == "running", Connections: response.Connections, EventCount: response.EventCount, RequestRate: response.RequestRate, Listeners: response.ListenerPorts}, nil
}

// Engines returns active remote sender metrics.
func (c *Client) Engines(ctx context.Context) ([]EngineInfo, error) {
	response, err := c.Do(ctx, Request{Command: "engines"})
	return response.Engines, err
}

// Listeners returns active remote receiver endpoints.
func (c *Client) Listeners(ctx context.Context) ([]ListenerInfo, error) {
	response, err := c.Do(ctx, Request{Command: "listener-ports"})
	return response.ListenerPorts, err
}

// EventsByPath queries remote events in an inclusive time range.
func (c *Client) EventsByPath(ctx context.Context, path string, start, end time.Time) ([]Event, error) {
	response, err := c.Do(ctx, Request{Command: "events", Path: path, Start: start, End: end})
	return response.Events, err
}

// ParentSummariesByPath queries remote parent summaries.
func (c *Client) ParentSummariesByPath(ctx context.Context, path, wildcard string, start, end time.Time) ([]ParentSummary, error) {
	response, err := c.Do(ctx, Request{Command: "path-parents", Path: path, Search: wildcard, Start: start, End: end})
	return response.Parents, err
}

// EventsSince queries remote events at or after since.
func (c *Client) EventsSince(ctx context.Context, since time.Time) ([]Event, error) {
	response, err := c.Do(ctx, Request{Command: "recent", Since: since})
	return response.Events, err
}

// Refresh requests application-supplied listener reconciliation.
func (c *Client) Refresh(ctx context.Context) error {
	_, err := c.Do(ctx, Request{Command: "fpolicy-refresh"})
	return err
}

// ResetEvents removes remote event indexes while preserving mappings.
func (c *Client) ResetEvents(ctx context.Context) error {
	_, err := c.Do(ctx, Request{Command: "events-reset"})
	return err
}

// Retention returns the remote retention duration. Zero means disabled.
func (c *Client) Retention(ctx context.Context) (time.Duration, error) {
	response, err := c.Do(ctx, Request{Command: "retention-show"})
	return response.Retention, err
}

// SetRetention persists retention remotely and returns the number of immediately deleted events.
func (c *Client) SetRetention(ctx context.Context, retention time.Duration) (uint64, error) {
	response, err := c.Do(ctx, Request{Command: "retention-set", Retention: retention})
	return response.DeletedEvents, err
}

// Stop requests graceful receiver shutdown.
func (c *Client) Stop(ctx context.Context) error {
	_, err := c.Do(ctx, Request{Command: "stop"})
	return err
}

func (r *Receiver) startControl() error {
	if err := os.MkdirAll(filepath.Dir(r.config.ControlPath), 0o755); err != nil {
		return fmt.Errorf("create control socket directory: %w", err)
	}
	if err := os.Remove(r.config.ControlPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	listener, err := net.Listen("unix", r.config.ControlPath)
	if err != nil {
		return fmt.Errorf("listen for control requests: %w", err)
	}
	r.mu.Lock()
	r.control = listener
	r.mu.Unlock()
	r.workers.Add(1)
	go r.acceptControl(listener)
	return nil
}

func (r *Receiver) acceptControl(listener net.Listener) {
	defer r.workers.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || r.contextDone() {
				return
			}
			r.logf("accept control connection: %v", err)
			continue
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			_ = connection.Close()
			return
		}
		r.connections[connection] = struct{}{}
		r.workers.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workers.Done()
			defer func() {
				r.mu.Lock()
				delete(r.connections, connection)
				r.mu.Unlock()
				_ = connection.Close()
			}()
			stop, err := r.handleControl(connection)
			if err != nil {
				r.logf("handle control request from %s: %v", connection.RemoteAddr(), err)
			}
			if stop {
				r.mu.Lock()
				cancel := r.cancel
				r.mu.Unlock()
				cancel()
			}
		}()
	}
}

func (r *Receiver) handleControl(connection net.Conn) (bool, error) {
	var request Request
	response := Response{}
	stop := false
	if err := json.NewDecoder(io.LimitReader(connection, 1024*1024)).Decode(&request); err != nil {
		response.Error = "invalid request: " + err.Error()
	} else {
		var err error
		switch request.Command {
		case "status":
			var status Status
			status, err = r.Status()
			response.Status = "running"
			response.Connections = status.Connections
			response.EventCount = status.EventCount
			response.RequestRate = status.RequestRate
			response.ListenerPorts = status.Listeners
		case "engines":
			response.Engines = r.Engines()
		case "fpolicy-refresh":
			err = r.Refresh()
			if err == nil {
				response.Status = "refreshed"
			}
		case "listener-ports":
			response.ListenerPorts = r.Listeners()
		case "stop":
			response.Status = "stopping"
			stop = true
		case "events":
			response.Events, err = r.db.EventsByPath(request.Path, request.Start, request.End)
		case "path-parents":
			response.Parents, err = r.db.ParentSummariesByPath(request.Path, request.Search, request.Start, request.End)
		case "recent":
			response.Events, err = r.db.EventsSince(request.Since)
		case "volume-set":
			err = r.db.SetVolumeName(request.VolumeMSID, request.VolumeName)
			if err == nil {
				response.Status = "updated"
			}
		case "volume-list":
			response.Mappings, err = r.db.ListVolumeMappings()
		case "svm-set":
			err = r.db.SetSVMName(request.SVMID, request.SVMName)
			if err == nil {
				response.Status = "updated"
			}
		case "volume-svm-set":
			err = r.db.SetVolumeSVMName(request.VolumeMSID, request.SVMName)
			if err == nil {
				response.Status = "updated"
			}
		case "parent-mappings-set":
			err = r.db.CacheParentMappings(request.Parents)
			if err == nil {
				response.Status = "updated"
			}
		case "svm-list":
			response.Mappings, err = r.db.ListSVMMappings()
		case "events-reset":
			err = r.db.ResetEvents()
			if err == nil {
				response.Status = "reset"
			}
		case "retention-show":
			response.Retention, _, err = r.db.Retention()
		case "retention-set":
			err = r.db.SetRetention(request.Retention)
			if err == nil {
				response.DeletedEvents, err = r.db.ApplyRetention(time.Now().UTC())
				response.Retention = request.Retention
				response.Status = "updated"
			}
		case "db-status":
			var stats DatabaseStats
			stats, err = r.db.Stats()
			response.DBPath = stats.Path
			response.DBSize = stats.Size
		default:
			response.Error = "unknown command"
		}
		if err != nil {
			response.Error = err.Error()
		}
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return false, fmt.Errorf("encode control response for %q: %w", request.Command, err)
	}
	return stop, nil
}
