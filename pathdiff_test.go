package pathdiff_test

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/otuschhoff/pathdiff"
)

func TestDatabasePublicAPI(t *testing.T) {
	database, err := pathdiff.OpenDatabase(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	timestamp := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	if err := database.Store(pathdiff.Event{Path: "/vol/data/file", Operation: "write", Timestamp: timestamp}); err != nil {
		t.Fatal(err)
	}
	events, err := database.EventsByPath("/vol/data", timestamp, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Path != "/vol/data/file" {
		t.Fatalf("EventsByPath() = %#v", events)
	}
}

func TestReceiverRestoresPersistedListeners(t *testing.T) {
	directory := t.TempDir()
	database, err := pathdiff.OpenDatabase(directory)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := database.SetListenerSnapshot(pathdiff.ListenerSnapshot{UpdatedAt: time.Now().UTC(), Listeners: []pathdiff.ListenerConfig{{Address: address, AllowedSources: []string{"127.0.0.1"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	receiver, err := pathdiff.NewReceiver(pathdiff.Config{DatabasePath: directory, RestoreListeners: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := receiver.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	listeners := receiver.Listeners()
	if len(listeners) != 1 || listeners[0].Address != address {
		t.Fatalf("restored listeners = %#v", listeners)
	}

	event := pathdiff.Event{Path: "/vol/app/file", Operation: "write", Timestamp: time.Now().UTC()}
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(connection).Encode(event); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		senders, err := receiver.Database().Senders()
		if err != nil {
			t.Fatal(err)
		}
		if len(senders) == 1 && senders[0].LIFIPv4 == "127.0.0.1" && senders[0].TotalEvents == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	senders, _ := receiver.Database().Senders()
	t.Fatalf("persisted senders = %#v", senders)
}

func TestEmbeddedReceiverAndRemoteClient(t *testing.T) {
	controlPath := filepath.Join(t.TempDir(), "pathdiff.sock")
	receiver, err := pathdiff.NewReceiver(pathdiff.Config{
		DatabasePath: t.TempDir(),
		ControlPath:  controlPath,
		Listeners:    []pathdiff.ListenerConfig{{Address: "127.0.0.1:0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := receiver.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Close() })

	listeners := receiver.Listeners()
	if len(listeners) != 1 || listeners[0].Address == "" {
		t.Fatalf("Listeners() = %#v", listeners)
	}
	connection, err := net.Dial("tcp", listeners[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	event := pathdiff.Event{Path: "/vol/app/file", Operation: "write", Timestamp: time.Now().UTC()}
	if err := json.NewEncoder(connection).Encode(event); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	var direct []pathdiff.Event
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		direct, err = receiver.Database().EventsByPath("/vol/app", event.Timestamp.Add(-time.Second), event.Timestamp.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if len(direct) == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(direct) != 1 || direct[0].Path != event.Path {
		t.Fatalf("direct query = %#v", direct)
	}

	client := pathdiff.NewClient(controlPath)
	remote, err := client.EventsByPath(context.Background(), "/vol/app", event.Timestamp.Add(-time.Second), event.Timestamp.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(remote) != 1 || remote[0].Path != event.Path {
		t.Fatalf("remote query = %#v", remote)
	}
	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Running || status.EventCount != 1 || len(status.Listeners) != 1 {
		t.Fatalf("remote status = %#v", status)
	}

	if err := receiver.SetListeners(nil); err != nil {
		t.Fatal(err)
	}
	if listeners := receiver.Listeners(); len(listeners) != 0 {
		t.Fatalf("listeners after reconciliation = %#v", listeners)
	}
	if err := client.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Wait(); err != nil {
		t.Fatal(err)
	}
}
