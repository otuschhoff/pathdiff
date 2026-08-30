package store

import (
	"os"
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

func TestParentSummariesByPath(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	base := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	for _, event := range []Event{
		{Path: "/otusch/alpha/a", Operation: "write", Timestamp: base, VolumeMSID: "10", SVMID: "20"},
		{Path: "/otusch/alpha/a", Operation: "rename", Timestamp: base.Add(time.Minute), VolumeMSID: "10", SVMID: "20"},
		{Path: "/otusch/alpha/b", Operation: "write", Timestamp: base.Add(2 * time.Minute), VolumeMSID: "10"},
		{Path: "/otusch/beta/c", Operation: "write", Timestamp: base.Add(3 * time.Minute), VolumeMSID: "10", SVMID: "20"},
	} {
		if err := db.Store(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetVolumeName("10", "home"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVolumeSVMName("10", "svm-home-new"); err != nil {
		t.Fatal(err)
	}
	summaries, err := db.ParentSummariesByPath("/otusch", "*ALPHA*", base, base.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("ParentSummariesByPath() = %#v, want one summary", summaries)
	}
	summary := summaries[0]
	if summary.Path != "/otusch/alpha" || summary.ChildCount != 2 || !summary.Timestamp.Equal(base.Add(2*time.Minute)) || summary.VolumeName != "home" || summary.SVMID != "20" || summary.SVMName != "svm-home-new" {
		t.Fatalf("ParentSummariesByPath() = %#v", summary)
	}
	svmNames, err := db.mappingNames("s:")
	if err != nil {
		t.Fatal(err)
	}
	if svmNames["20"] != "svm-home-new" {
		t.Fatalf("SVM ID mapping was not backfilled: %#v", svmNames)
	}
}

func TestCacheParentMappingsPersists(t *testing.T) {
	path := t.TempDir()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CacheParentMappings([]ParentSummary{{VolumeMSID: "10", VolumeName: "home", SVMID: "20", SVMName: "svm-home"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for prefix, expected := range map[string]map[string]string{
		"v:": {"10": "home"},
		"w:": {"10": "svm-home"},
		"s:": {"20": "svm-home"},
	} {
		names, err := db.mappingNames(prefix)
		if err != nil {
			t.Fatal(err)
		}
		for id, name := range expected {
			if names[id] != name {
				t.Fatalf("mapping %q[%q] = %q, want %q", prefix, id, names[id], name)
			}
		}
	}
}

func TestDecodePathIndexKey(t *testing.T) {
	timestamp := time.Date(2026, 8, 30, 12, 34, 56, 123456789, time.UTC)
	key := pathKey("/otusch/cache:https/file", timestamp, "NFS_WR", "2163258291")
	path, decodedTimestamp, volumeMSID, err := decodePathIndexKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if string(path) != "/otusch/cache:https/file" || !decodedTimestamp.Equal(timestamp.Truncate(time.Microsecond)) || string(volumeMSID) != "2163258291" {
		t.Fatalf("decodePathIndexKey() = path %q, timestamp %s, volume %q", path, decodedTimestamp, volumeMSID)
	}
}

func BenchmarkParentSummariesByPath(b *testing.B) {
	path := os.Getenv("PATHDIFF_BENCH_DB")
	if path == "" {
		b.Skip("PATHDIFF_BENCH_DB is not set")
	}
	db, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := db.ParentSummariesByPath("", "*otusch*", start, end); err != nil {
			b.Fatal(err)
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

func TestStats(t *testing.T) {
	path := t.TempDir()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Store(Event{Path: "/vol/data/a", Operation: "NFS_WR"}); err != nil {
		t.Fatal(err)
	}
	stats, err := db.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Path != path || stats.Size == 0 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestListMappings(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.SetVolumeName("2", "beta"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVolumeName("1", "alpha"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSVMName("svm-1", "finance"); err != nil {
		t.Fatal(err)
	}
	volumes, err := db.ListVolumeMappings()
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 2 || volumes[0] != (Mapping{ID: "1", Name: "alpha"}) || volumes[1] != (Mapping{ID: "2", Name: "beta"}) {
		t.Fatalf("volume mappings = %#v", volumes)
	}
	svms, err := db.ListSVMMappings()
	if err != nil {
		t.Fatal(err)
	}
	if len(svms) != 1 || svms[0] != (Mapping{ID: "svm-1", Name: "finance"}) {
		t.Fatalf("SVM mappings = %#v", svms)
	}
}

func TestFPolicyLIFUnreachable(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.MarkFPolicyLIFUnreachable("finance", "finance_data", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if unreachable, err := db.FPolicyLIFUnreachable("finance", "finance_data", "192.0.2.10"); err != nil || !unreachable {
		t.Fatalf("same address unreachable = %t, err = %v", unreachable, err)
	}
	if unreachable, err := db.FPolicyLIFUnreachable("finance", "finance_data", "192.0.2.11"); err != nil || unreachable {
		t.Fatalf("changed address unreachable = %t, err = %v", unreachable, err)
	}
}
