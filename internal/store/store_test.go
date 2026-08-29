package store

import (
	"testing"
	"time"
)

func TestQueries(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	base := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	for _, event := range []Event{
		{Path: "/vol/data/a", Operation: "modify", Timestamp: base.Add(time.Minute)},
		{Path: "/vol/data/a", Operation: "rename", Timestamp: base.Add(2 * time.Minute)},
		{Path: "/vol/data/b", Operation: "create", Timestamp: base.Add(3 * time.Minute)},
		{Path: "/vol/database/c", Operation: "modify", Timestamp: base.Add(3 * time.Minute)},
	} {
		if err := db.Store(event); err != nil {
			t.Fatal(err)
		}
	}

	recent, err := db.EventsSince(base.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(recent), 3; got != want {
		t.Fatalf("EventsSince() returned %d events, want %d", got, want)
	}
	if recent[0].Timestamp.Before(base.Add(2 * time.Minute)) {
		t.Fatalf("EventsSince() included an event before its boundary: %#v", recent[0])
	}

	events, err := db.EventsByPath("/vol/data/", base, base.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("EventsByPath() returned %d events, want 3: %#v", len(events), events)
	}
	for _, event := range events {
		if event.Path == "/vol/database/c" {
			t.Fatalf("path-prefix query included sibling path: %#v", event)
		}
	}
}

func TestStoreDistinctPathsWithSameTimestamp(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	timestamp := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	for _, event := range []Event{
		{Path: "/vol/data/a", Operation: "NFS_WR", Timestamp: timestamp},
		{Path: "/vol/data/b", Operation: "NFS_WR", Timestamp: timestamp},
	} {
		if err := db.Store(event); err != nil {
			t.Fatal(err)
		}
	}
	events, err := db.EventsSince(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("EventsSince() returned %d events, want 2", len(events))
	}
}

func TestVolumeNameMapping(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	timestamp := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	if err := db.Store(Event{Path: "/otusch/data", Operation: "NFS_WR", Timestamp: timestamp, VolumeMSID: "2163258291"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVolumeName("2163258291", "asic_user"); err != nil {
		t.Fatal(err)
	}
	events, err := db.EventsSince(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].VolumeMSID != "2163258291" || events[0].VolumeName != "asic_user" {
		t.Fatalf("mapped events = %#v", events)
	}
}

func TestResetEventsPreservesVolumeMappings(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	timestamp := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	if err := db.SetVolumeName("2163258291", "asic_user"); err != nil {
		t.Fatal(err)
	}
	if err := db.Store(Event{Path: "/vol/old", Operation: "NFS_WR", Timestamp: timestamp, VolumeMSID: "2163258291"}); err != nil {
		t.Fatal(err)
	}
	if err := db.ResetEvents(); err != nil {
		t.Fatal(err)
	}
	events, err := db.EventsSince(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events after reset = %#v, want none", events)
	}
	if err := db.Store(Event{Path: "/vol/new", Operation: "NFS_WR", Timestamp: timestamp, VolumeMSID: "2163258291"}); err != nil {
		t.Fatal(err)
	}
	events, err = db.EventsSince(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].VolumeName != "asic_user" {
		t.Fatalf("volume mapping was not preserved: %#v", events)
	}
}
