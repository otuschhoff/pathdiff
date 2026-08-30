package store

import (
	"fmt"
	"os"
	"sync"
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

func TestConcurrentIngestionDuringPathQueries(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for index := range 5000 {
		if err := db.Store(Event{Path: fmt.Sprintf("/seed/parent-%04d/file", index), Operation: "write", Timestamp: base}); err != nil {
			t.Fatal(err)
		}
	}

	stopQueries := make(chan struct{})
	queryStarted := make(chan struct{})
	queryDone := make(chan error, 1)
	go func() {
		close(queryStarted)
		for {
			select {
			case <-stopQueries:
				queryDone <- nil
				return
			default:
				if _, err := db.ParentSummariesByPath("/seed", "*", base.Add(-time.Second), base.Add(time.Second)); err != nil {
					queryDone <- err
					return
				}
			}
		}
	}()
	<-queryStarted

	const writers = 4
	const eventsPerWriter = 500
	var writes sync.WaitGroup
	writeErrors := make(chan error, writers)
	for writer := range writers {
		writes.Add(1)
		go func() {
			defer writes.Done()
			for index := range eventsPerWriter {
				event := Event{Path: fmt.Sprintf("/live/writer-%d/file-%04d", writer, index), Operation: "write", Timestamp: base.Add(time.Duration(index+1) * time.Microsecond)}
				if err := db.Store(event); err != nil {
					writeErrors <- err
					return
				}
			}
		}()
	}
	writes.Wait()
	close(writeErrors)
	close(stopQueries)
	if err := <-queryDone; err != nil {
		t.Fatal(err)
	}
	for err := range writeErrors {
		t.Fatal(err)
	}

	events, err := db.EventsByPath("/live/", base, base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(events), writers*eventsPerWriter; got != want {
		t.Fatalf("EventsByPath() returned %d concurrently stored events, want %d", got, want)
	}
}

func TestScanQueryLimitReservesCapacity(t *testing.T) {
	for _, test := range []struct {
		processors int
		want       int
	}{{1, 1}, {2, 1}, {4, 1}, {8, 3}, {32, 4}} {
		if got := scanQueryLimit(test.processors); got != test.want {
			t.Errorf("scanQueryLimit(%d) = %d, want %d", test.processors, got, test.want)
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

func TestStorePreservesIdenticalConcurrentEvents(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	timestamp := time.Date(2026, 8, 30, 12, 0, 0, 123456000, time.UTC)
	event := Event{Path: "/vol/data/file", Operation: "NFS_WR", Timestamp: timestamp, VolumeMSID: "10"}

	const eventCount = 100
	var stores sync.WaitGroup
	storeErrors := make(chan error, eventCount)
	for range eventCount {
		stores.Add(1)
		go func() {
			defer stores.Done()
			if err := db.Store(event); err != nil {
				storeErrors <- err
			}
		}()
	}
	stores.Wait()
	close(storeErrors)
	for err := range storeErrors {
		t.Fatal(err)
	}

	events, err := db.EventsSince(timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != eventCount {
		t.Fatalf("EventsSince() returned %d identical events, want %d", len(events), eventCount)
	}
	summaries, err := db.ParentSummariesByPath("/vol", "*", timestamp, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].ChildCount != 1 {
		t.Fatalf("ParentSummariesByPath() = %#v, want one unique child", summaries)
	}
	deleted, err := db.DeleteEventsBefore(timestamp.Add(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if deleted != eventCount {
		t.Fatalf("DeleteEventsBefore() deleted %d events, want %d", deleted, eventCount)
	}
	events, err = db.EventsByPath("/vol", timestamp, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("EventsByPath() returned %d events after retention", len(events))
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

func TestRetentionPersistsAndDeletesBothIndexes(t *testing.T) {
	path := t.TempDir()
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	if _, enabled, err := db.Retention(); err != nil || enabled {
		t.Fatalf("default retention = enabled %t, err %v", enabled, err)
	}
	if err := db.SetRetention(24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.SetVolumeName("10", "home"); err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{
		{Path: "/old/file", Operation: "write", Timestamp: now.Add(-25 * time.Hour), VolumeMSID: "10"},
		{Path: "/cutoff/file", Operation: "write", Timestamp: now.Add(-24 * time.Hour), VolumeMSID: "10"},
		{Path: "/recent/file", Operation: "write", Timestamp: now.Add(-time.Hour), VolumeMSID: "10"},
	} {
		if err := db.Store(event); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := db.ApplyRetention(now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("ApplyRetention() deleted %d events, want 1", deleted)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	retention, enabled, err := db.Retention()
	if err != nil || !enabled || retention != 24*time.Hour {
		t.Fatalf("persisted retention = %s, enabled %t, err %v", retention, enabled, err)
	}
	events, err := db.EventsSince(now.Add(-24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Path != "/cutoff/file" || events[1].Path != "/recent/file" {
		t.Fatalf("time index after retention = %#v", events)
	}
	events, err = db.EventsByPath("/old", time.Time{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("path index retained expired events: %#v", events)
	}
	mappings, err := db.ListVolumeMappings()
	if err != nil || len(mappings) != 1 || mappings[0].Name != "home" {
		t.Fatalf("volume mappings after retention = %#v, err %v", mappings, err)
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
