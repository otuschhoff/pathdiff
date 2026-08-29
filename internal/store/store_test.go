package store

import (
	"reflect"
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
		{Inode: 7, Path: "/vol/data/a", Operation: "modify", Timestamp: base.Add(time.Minute)},
		{Inode: 7, Path: "/vol/data/a", Operation: "rename", Timestamp: base.Add(2 * time.Minute)},
		{Inode: 9, Path: "/vol/data/b", Operation: "create", Timestamp: base.Add(3 * time.Minute)},
		{Inode: 11, Path: "/vol/database/c", Operation: "modify", Timestamp: base.Add(3 * time.Minute)},
	} {
		if err := db.Store(event); err != nil {
			t.Fatal(err)
		}
	}

	inodes, err := db.InodesSince(base.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{7, 9, 11}; !reflect.DeepEqual(inodes, want) {
		t.Fatalf("InodesSince() = %v, want %v", inodes, want)
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
