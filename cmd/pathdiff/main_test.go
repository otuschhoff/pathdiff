package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/pathdiff/internal/store"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced output failure")
}

func TestParseTimeExpression(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC)
	for _, test := range []struct {
		value  string
		offset time.Duration
		want   time.Time
	}{
		{value: "", offset: -24 * time.Hour, want: now.Add(-24 * time.Hour)},
		{value: "2026-08-28", want: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)},
		{value: "10d", want: now.AddDate(0, 0, -10)},
		{value: "1m", want: now.Add(-time.Minute)},
		{value: "5h10m", want: now.Add(-(5*time.Hour + 10*time.Minute))},
		{value: "1M4d", want: now.AddDate(0, -1, -4)},
		{value: "2026-08-29T10:30:00Z", want: time.Date(2026, 8, 29, 10, 30, 0, 0, time.UTC)},
	} {
		got, err := parseTimeExpression("time", test.value, now, test.offset)
		if err != nil {
			t.Fatalf("parseTimeExpression(%q) returned error: %v", test.value, err)
		}
		if !got.Equal(test.want) {
			t.Fatalf("parseTimeExpression(%q) = %s, want %s", test.value, got, test.want)
		}
	}
}

func TestParseTimeExpressionRejectsInvalidValue(t *testing.T) {
	_, err := parseTimeExpression("start", "tomorrow", time.Now(), 0)
	if err == nil {
		t.Fatal("parseTimeExpression accepted an invalid value")
	}
}

func TestPrintEventsFiltersAndRendersTable(t *testing.T) {
	var output bytes.Buffer
	events := []store.Event{
		{Path: "/vol/finance/report.csv", Operation: "NFS_WR", Timestamp: time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC), VolumeMSID: "1", VolumeName: "asic_user"},
		{Path: "/vol/engineering/main.go", Operation: "NFS_WR", Timestamp: time.Date(2026, 8, 29, 11, 0, 0, 0, time.UTC)},
	}
	if err := printEvents(&output, events, normalizePathSearch("FINANCE"), 100); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "report.csv") || !strings.Contains(got, "asic_user") || strings.Contains(got, "main.go") {
		t.Fatalf("unexpected table output: %s", got)
	}
}

func TestNormalizePathSearch(t *testing.T) {
	if got := normalizePathSearch("firefox"); got != "*firefox*" {
		t.Fatalf("normalizePathSearch() = %q, want %q", got, "*firefox*")
	}
	if got := normalizePathSearch("*/firefox/*"); got != "*/firefox/*" {
		t.Fatalf("normalizePathSearch() changed wildcard pattern to %q", got)
	}
}

func TestPrintEventsLimitsResults(t *testing.T) {
	var output bytes.Buffer
	events := []store.Event{{Path: "/vol/a", Operation: "NFS_WR"}, {Path: "/vol/b", Operation: "NFS_WR"}}
	if err := printEvents(&output, events, "*", 1); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, highlightQueryHint("2")) || !strings.Contains(got, highlightQueryHint("--max")) || !strings.Contains(got, highlightQueryHint("--path")) {
		t.Fatalf("unexpected limit output: %s", got)
	}
}

func TestPrintPathsCoalescesAndSorts(t *testing.T) {
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	events := []store.Event{
		{Path: "/vol/z", Operation: "NFS_WR", Timestamp: base, VolumeName: "beta"},
		{Path: "/vol/a", Operation: "NFS_WR", Timestamp: base.Add(time.Minute), VolumeName: "alpha"},
		{Path: "/vol/a", Operation: "NFS_SET_ATTR", Timestamp: base.Add(2 * time.Minute), VolumeName: "alpha"},
	}
	var output bytes.Buffer
	if err := printPaths(&output, events, "*", 100, "path"); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "/vol/a") != 1 || !strings.Contains(got, "2026-08-29T12:02:00Z") {
		t.Fatalf("paths were not coalesced to latest change: %s", got)
	}
	if strings.Index(got, "alpha") > strings.Index(got, "beta") {
		t.Fatalf("paths were not sorted by volume: %s", got)
	}

	output.Reset()
	if err := printPaths(&output, events, "*", 100, "timestamp"); err != nil {
		t.Fatal(err)
	}
	if strings.Index(output.String(), "/vol/a") > strings.Index(output.String(), "/vol/z") {
		t.Fatalf("paths were not sorted newest first: %s", output.String())
	}
}

func TestPrintPathsLimitsCoalescedResults(t *testing.T) {
	var output bytes.Buffer
	events := []store.Event{{Path: "/vol/a", VolumeName: "one"}, {Path: "/vol/a", VolumeName: "one"}, {Path: "/vol/b", VolumeName: "one"}}
	if err := printPaths(&output, events, "*", 1, "path"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, highlightQueryHint("2")) || !strings.Contains(got, highlightQueryHint("--max")) || !strings.Contains(got, highlightQueryHint("--path")) {
		t.Fatalf("unexpected path limit output: %s", got)
	}
}

func TestPrintParentSummaries(t *testing.T) {
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	summaries := []store.ParentSummary{
		{Path: "/vol/alpha", Timestamp: base.Add(2 * time.Minute), ChildCount: 2, VolumeName: "one", SVMName: "svm-one"},
		{Path: "/vol/beta", Timestamp: base, ChildCount: 1, VolumeName: "one", SVMName: "svm-one"},
	}
	var output bytes.Buffer
	if err := printParentSummaries(&output, summaries, 100, "path"); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "/vol/alpha") != 1 || strings.Count(got, "/vol/beta") != 1 || !strings.Contains(got, "2026-08-29T12:02:00Z") || !strings.Contains(got, "svm-one") || !strings.Contains(got, "one") || !strings.Contains(got, "CNT") {
		t.Fatalf("unexpected parent summaries: %s", got)
	}
}

func TestPrintParentSummariesEmpty(t *testing.T) {
	var output bytes.Buffer
	if err := printParentSummaries(&output, nil, 100, "path"); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), "No records found.\n"; got != want {
		t.Fatalf("empty parent summaries output = %q, want %q", got, want)
	}
}

func TestPrintParentSummariesHighlightsLimitHints(t *testing.T) {
	summaries := []store.ParentSummary{{Path: "/one"}, {Path: "/two"}}
	var output bytes.Buffer
	if err := printParentSummaries(&output, summaries, 1, "path"); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, value := range []string{"2", "--max", "--path"} {
		if !strings.Contains(got, highlightQueryHint(value)) {
			t.Errorf("limit output does not highlight %q: %q", value, got)
		}
	}
}

func TestPathExportFlags(t *testing.T) {
	for _, newCommand := range []func() *cobra.Command{newPathListCommand, newPathParentCommand} {
		command := newCommand()
		if err := command.ParseFlags([]string{"--json"}); err != nil {
			t.Fatal(err)
		}
		if value, err := command.Flags().GetString("json"); err != nil || value != automaticExportFilename {
			t.Fatalf("bare --json = %q, %v", value, err)
		}

		command = newCommand()
		if err := command.ParseFlags([]string{"--json=results.json"}); err != nil {
			t.Fatal(err)
		}
		if value, err := command.Flags().GetString("json"); err != nil || value != "results.json" {
			t.Fatalf("explicit --json = %q, %v", value, err)
		}

		command = newCommand()
		if err := command.ParseFlags([]string{"--json", "--jsonl"}); err != nil {
			t.Fatal(err)
		}
		if err := command.ValidateFlagGroups(); err == nil {
			t.Fatal("--json and --jsonl were accepted together")
		}
	}
}

func TestExportPathRecordsJSONIncludesAllResults(t *testing.T) {
	events := []store.Event{
		{Path: "/vol/a", Timestamp: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)},
		{Path: "/vol/b", Timestamp: time.Date(2026, 8, 30, 12, 1, 0, 0, time.UTC)},
		{Path: "/vol/c", Timestamp: time.Date(2026, 8, 30, 12, 2, 0, 0, time.UTC)},
	}
	results, err := pathRows(events, "*", "path", func(event store.Event) string { return event.Path })
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "paths.json")
	var output bytes.Buffer
	if err := exportPathRecords(&output, results, "json", filename, "list", time.Time{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var exported []store.Event
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != 3 {
		t.Fatalf("JSON export contains %d records, want all 3 despite a display max of 1", len(exported))
	}
	if !strings.Contains(output.String(), "Exported 3 records to "+filename) {
		t.Fatalf("unexpected export output: %s", output.String())
	}
}

func TestExportPathRecordsJSONL(t *testing.T) {
	records := []store.ParentSummary{{Path: "/one"}, {Path: "/two"}}
	filename := filepath.Join(t.TempDir(), "parents.jsonl")
	if err := exportPathRecords(io.Discard, records, "jsonl", filename, "parent", time.Time{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("JSONL export has %d lines, want 2: %q", len(lines), data)
	}
	for _, line := range lines {
		var summary store.ParentSummary
		if err := json.Unmarshal([]byte(line), &summary); err != nil {
			t.Fatalf("invalid JSONL record %q: %v", line, err)
		}
	}
}

func TestExportPathRecordsEmptyJSONArray(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "empty.json")
	if err := exportPathRecords[store.Event](io.Discard, nil, "json", filename, "list", time.Time{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("empty JSON export = %q, want []", data)
	}
}

func TestPathExportFilename(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 34, 56, 123456789, time.FixedZone("test", 2*60*60))
	if got, want := pathExportFilename(automaticExportFilename, "parent", "jsonl", now), "pathdiff-path-parent-20260830T103456.123456789Z.jsonl"; got != want {
		t.Fatalf("automatic export filename = %q, want %q", got, want)
	}
	if got := pathExportFilename("custom.json", "list", "json", now); got != "custom.json" {
		t.Fatalf("explicit export filename = %q", got)
	}
}

func TestPathCommandsExportAllResultsBeyondMax(t *testing.T) {
	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		command    func() *cobra.Command
		response   controlResponse
		flag       string
		filename   string
		wantRecord int
	}{
		{
			name:       "list JSON",
			command:    newPathListCommand,
			response:   controlResponse{Events: []store.Event{{Path: "/one", Timestamp: base}, {Path: "/two", Timestamp: base}}},
			flag:       "--json",
			filename:   "paths.json",
			wantRecord: 2,
		},
		{
			name:       "parent JSONL",
			command:    newPathParentCommand,
			response:   controlResponse{Parents: []store.ParentSummary{{Path: "/one", Timestamp: base, VolumeName: "vol", SVMName: "svm"}, {Path: "/two", Timestamp: base, VolumeName: "vol", SVMName: "svm"}}},
			flag:       "--jsonl",
			filename:   "parents.jsonl",
			wantRecord: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			controlPath := filepath.Join(directory, "control.sock")
			listener, err := net.Listen("unix", controlPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			served := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					served <- err
					return
				}
				defer connection.Close()
				var request controlRequest
				if err := json.NewDecoder(connection).Decode(&request); err != nil {
					served <- err
					return
				}
				served <- json.NewEncoder(connection).Encode(test.response)
			}()

			filename := filepath.Join(directory, test.filename)
			command := test.command()
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			command.SetArgs([]string{"--control", controlPath, "--max", "1", test.flag + "=" + filename})
			if err := command.Execute(); err != nil {
				t.Fatal(err)
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if test.flag == "--json" {
				var records []store.Event
				if err := json.Unmarshal(data, &records); err != nil {
					t.Fatal(err)
				}
				if len(records) != test.wantRecord {
					t.Fatalf("exported %d records, want %d", len(records), test.wantRecord)
				}
			} else {
				if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != test.wantRecord {
					t.Fatalf("exported %d JSONL records, want %d", lines, test.wantRecord)
				}
			}
			if !strings.Contains(output.String(), fmt.Sprintf("Exported %d records", test.wantRecord)) {
				t.Fatalf("unexpected command output: %s", output.String())
			}
		})
	}
}

func TestResolveParentSummaries(t *testing.T) {
	summaries := []store.ParentSummary{{VolumeMSID: "2163258291", SVMID: "svm-id"}}
	if !parentSummariesNeedResolution(summaries) {
		t.Fatal("unresolved parent summary was not detected")
	}
	resolveParentSummaries(summaries, map[string]monitorVolume{"2163258291": {Name: "asic_user", SVM: "ncl1-1-vs-50"}})
	if summaries[0].VolumeName != "asic_user" || summaries[0].SVMName != "ncl1-1-vs-50" || parentSummariesNeedResolution(summaries) {
		t.Fatalf("parent summary was not resolved: %#v", summaries[0])
	}
}

func TestServiceFormatting(t *testing.T) {
	if got := formatCount(1234567); got != "1,234,567" {
		t.Fatalf("formatCount() = %q", got)
	}
	unit := systemdUnit([]string{"/opt/pathdiff", "daemon", "run"})
	if !strings.Contains(unit, "ExecStart=/opt/pathdiff daemon run") || !strings.Contains(unit, "Restart=on-failure") {
		t.Fatalf("unexpected systemd unit: %s", unit)
	}
	if got := formatHealthCount(0); got != text.FgRed.Sprint("0") {
		t.Fatalf("formatHealthCount(0) = %q", got)
	}
	if got := formatHealthCount(2); got != "2" {
		t.Fatalf("formatHealthCount(2) = %q", got)
	}
}

func TestPrintMonitorEvents(t *testing.T) {
	events := []store.Event{{Path: "/vol/finance/report.csv", Operation: "write", Timestamp: time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC), VolumeName: "finance", SVMName: "ncl1-1-vs-50", NodeID: "node-1", LIFIPv4: "192.0.2.10"}}
	var output bytes.Buffer
	if err := printMonitorEvents(&output, events, monitorOptions{ShowNode: true, ShowLIF: true, ShowOperation: true}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "VOLUME") || !strings.Contains(got, "SVM") || !strings.Contains(got, "NODE") || !strings.Contains(got, "LIF") || !strings.Contains(got, "finance") || !strings.Contains(got, "192.0.2.10") {
		t.Fatalf("unexpected monitor output: %s", got)
	}
	output.Reset()
	if err := printMonitorEvents(&output, events, monitorOptions{HideTimestamp: true, HideVolume: true, HideSVM: true}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); strings.Contains(got, "TIMESTAMP") || strings.Contains(got, "OPERATION") || strings.Contains(got, "VOLUME") || strings.Contains(got, "SVM") || !strings.Contains(got, "PATH") {
		t.Fatalf("unexpected hidden monitor output: %s", got)
	}
}

func TestNewestMonitorEventsByPath(t *testing.T) {
	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	events := newestMonitorEventsByPath([]store.Event{{Path: "/one", Operation: "create", Timestamp: base}, {Path: "/one", Operation: "write", Timestamp: base.Add(time.Second)}, {Path: "/two", Timestamp: base}})
	if len(events) != 2 || events[1].Path != "/one" || events[1].Operation != "write" {
		t.Fatalf("newest monitor events = %#v", events)
	}
}

func TestResolveMonitorEvent(t *testing.T) {
	event := store.Event{VolumeMSID: "2163258291"}
	resolveMonitorEvent(&event, map[string]monitorVolume{"2163258291": {Name: "home", SVM: "ncl1-1-vs-50"}})
	if event.VolumeName != "home" || event.SVMName != "ncl1-1-vs-50" {
		t.Fatalf("resolved event = %#v", event)
	}
}

func TestEventFilters(t *testing.T) {
	event := store.Event{Path: "/vol/finance/report.csv", SVMName: "ncl1-1-vs-50", SVMID: "svm-1", VolumeName: "finance", VolumeMSID: "2163258291", NodeID: "ncl1-1-ps-07", LIFIPv4: "192.0.2.10"}
	for _, test := range []struct {
		name    string
		filters eventFilters
		want    bool
	}{
		{name: "no filters", want: true},
		{name: "svm name", filters: eventFilters{SVMs: []string{"vs-50"}}, want: true},
		{name: "svm id", filters: eventFilters{SVMs: []string{"svm-1"}}, want: true},
		{name: "svm alternatives", filters: eventFilters{SVMs: []string{"vs-60", "vs-50"}}, want: true},
		{name: "svm mismatch", filters: eventFilters{SVMs: []string{"vs-60"}}, want: false},
		{name: "volume msid", filters: eventFilters{Volumes: []string{"2163258291"}}, want: true},
		{name: "volume wildcard", filters: eventFilters{Volumes: []string{"fin*"}}, want: true},
		{name: "node", filters: eventFilters{Nodes: []string{"ps-07"}}, want: true},
		{name: "lif", filters: eventFilters{LIFs: []string{"192.0.2.10"}}, want: true},
		{name: "combined match", filters: eventFilters{SVMs: []string{"vs-50"}, Volumes: []string{"finance"}, Nodes: []string{"ps-07"}, LIFs: []string{"192.0.2.10"}}, want: true},
		{name: "combined mismatch", filters: eventFilters{SVMs: []string{"vs-50"}, Volumes: []string{"home"}}, want: false},
	} {
		if got := test.filters.matches(event); got != test.want {
			t.Fatalf("%s: matches() = %t, want %t", test.name, got, test.want)
		}
	}
	if matchesFilter([]string{"node-1"}, "") {
		t.Fatal("empty event metadata matched a filter")
	}
	filters := eventFilters{SVMs: []string{"vs-50"}}
	events := filters.filterEvents([]store.Event{event, {Path: "/other", SVMName: "ncl1-1-vs-60"}})
	if len(events) != 1 || events[0].Path != event.Path {
		t.Fatalf("filterEvents() = %#v", events)
	}
	summaries := filters.filterSummaries([]store.ParentSummary{{Path: "/vol/finance", SVMName: "ncl1-1-vs-50"}, {Path: "/vol/other", SVMID: "svm-9"}})
	if len(summaries) != 1 || summaries[0].Path != "/vol/finance" {
		t.Fatalf("filterSummaries() = %#v", summaries)
	}
}

func TestFilterFlagsAreRepeatable(t *testing.T) {
	for _, test := range []struct {
		command *cobra.Command
		names   []string
	}{
		{command: newMonitorCommand(), names: []string{"svm", "volume", "node", "lif"}},
		{command: newEventsCommand(), names: []string{"svm", "volume", "node", "lif"}},
		{command: newPathListCommand(), names: []string{"svm", "volume", "node", "lif"}},
		{command: newPathParentCommand(), names: []string{"svm", "volume"}},
		{command: newVolumeSummaryCommand(), names: []string{"svm", "volume"}},
	} {
		for _, name := range test.names {
			flag := test.command.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("%s: --%s is not registered", test.command.Name(), name)
			}
			if flag.Value.Type() != "stringArray" {
				t.Fatalf("%s: --%s type = %s, want stringArray", test.command.Name(), name, flag.Value.Type())
			}
		}
	}
}

func TestAggregateVolumeSummaries(t *testing.T) {
	summaries := []store.ParentSummary{
		{Path: "/vol/finance/reports", SVMName: "ncl1-1-vs-50", VolumeName: "finance", ChildCount: 3},
		{Path: "/vol/finance/archive", SVMName: "ncl1-1-vs-50", VolumeName: "finance", ChildCount: 4},
		{Path: "/vol/home/users", SVMName: "ncl1-1-vs-50", VolumeMSID: "2163258291", ChildCount: 2},
		{Path: "/vol/finance/shared", SVMID: "svm-9", VolumeName: "finance", ChildCount: 1},
	}
	volumes, err := aggregateVolumeSummaries(summaries, "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 3 {
		t.Fatalf("volumes = %#v", volumes)
	}
	if volumes[0].SVM != "ncl1-1-vs-50" || volumes[0].Volume != "2163258291" || volumes[0].Changes != 2 {
		t.Fatalf("first volume = %#v", volumes[0])
	}
	if volumes[1].Volume != "finance" || volumes[1].Changes != 7 {
		t.Fatalf("aggregated volume = %#v", volumes[1])
	}
	if volumes[2].SVM != "svm-9" || volumes[2].Changes != 1 {
		t.Fatalf("unresolved SVM volume = %#v", volumes[2])
	}
	filtered, err := aggregateVolumeSummaries(summaries, normalizePathSearch("fin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 2 || filtered[0].Volume != "finance" {
		t.Fatalf("filtered volumes = %#v", filtered)
	}
}

func TestPrintVolumeSummaries(t *testing.T) {
	var output bytes.Buffer
	if err := printVolumeSummaries(&output, []volumeSummary{{SVM: "ncl1-1-vs-50", Volume: "finance", Changes: 7}}, 100); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "SVM") || !strings.Contains(got, "CNT") || !strings.Contains(got, "finance") || !strings.Contains(got, "7") || strings.Contains(got, "Parent") {
		t.Fatalf("unexpected volume table: %s", got)
	}
	output.Reset()
	if err := printVolumeSummaries(&output, nil, 100); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "No records found.") {
		t.Fatalf("unexpected empty output: %s", got)
	}
	output.Reset()
	if err := printVolumeSummaries(&output, []volumeSummary{{Volume: "one"}, {Volume: "two"}}, 1); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "changed volumes match") {
		t.Fatalf("unexpected over-limit output: %s", got)
	}
}

func TestVolumeCommandRegistered(t *testing.T) {
	root := newRootCommand()
	command, remaining, err := root.Find([]string{"volume"})
	if err != nil || len(remaining) != 0 || command == nil || command.Name() != "volume" {
		t.Fatalf("Find(volume) = command %v, remaining %v, err %v", command, remaining, err)
	}
	if command.GroupID != "queries" {
		t.Fatalf("volume group = %q", command.GroupID)
	}
}

func TestMonitorJSONOutput(t *testing.T) {
	event := store.Event{Path: "/vol/finance/report.csv", VolumeName: "finance", SVMName: "ncl1-1-vs-50"}
	var output bytes.Buffer
	if err := json.NewEncoder(&output).Encode(event); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, `"volume_name":"finance"`) || !strings.Contains(got, `"svm_name":"ncl1-1-vs-50"`) {
		t.Fatalf("unexpected monitor JSON: %s", got)
	}
}

func TestDatabaseStatusFormatting(t *testing.T) {
	if got := formatBytes(1536); got != "1.5 KiB" {
		t.Fatalf("formatBytes() = %q", got)
	}
	var output bytes.Buffer
	if err := printDBStatus(&output, controlResponse{DBPath: "pathdiff_data", DBSize: 1536}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "PATH") || !strings.Contains(got, "pathdiff_data") || !strings.Contains(got, "1.5 KiB") {
		t.Fatalf("unexpected database status output: %s", got)
	}
}

func TestRetentionDurationAndFormatting(t *testing.T) {
	for value, expected := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "36h": 36 * time.Hour, "90m": 90 * time.Minute} {
		duration, err := parseRetentionDuration(value)
		if err != nil || duration != expected {
			t.Fatalf("parseRetentionDuration(%q) = %s, %v; want %s", value, duration, err, expected)
		}
	}
	for _, value := range []string{"", "0", "0d", "forever"} {
		if _, err := parseRetentionDuration(value); err == nil {
			t.Fatalf("parseRetentionDuration(%q) succeeded", value)
		}
	}
	var output bytes.Buffer
	if err := printRetention(&output, controlResponse{Retention: 30 * 24 * time.Hour, DeletedEvents: 42}, true); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "30d") || !strings.Contains(got, "42") || !strings.Contains(got, "EXPIRED EVENTS DELETED") {
		t.Fatalf("unexpected retention output: %s", got)
	}
	output.Reset()
	if err := printRetention(&output, controlResponse{}, false); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "disabled") || strings.Contains(got, "EXPIRED EVENTS") {
		t.Fatalf("unexpected disabled retention output: %s", got)
	}
}

func TestRetentionCommandsRegistered(t *testing.T) {
	root := newRootCommand()
	for _, arguments := range [][]string{{"db", "retention", "show"}, {"db", "retention", "set"}} {
		command, remaining, err := root.Find(arguments)
		if err != nil || len(remaining) != 0 || command == nil {
			t.Fatalf("Find(%v) = command %v, remaining %v, err %v", arguments, command, remaining, err)
		}
	}
}

func TestEngineSnapshotAndFormatting(t *testing.T) {
	engines := []engineInfo{{
		Since:       time.Now().UTC().Add(-time.Minute),
		TotalEvents: 43120,
		AverageRate: 718.6,
		LIFIPv4:     "192.0.2.10",
		NodeID:      "node-1",
		SVMID:       "svm-1",
		LocalPort:   "9911",
		LastSeen:    time.Now().UTC().Add(-time.Minute),
	}}
	if len(engines) != 1 || engines[0].LIFIPv4 != "192.0.2.10" || engines[0].TotalEvents != 43120 || engines[0].LocalPort != "9911" || engines[0].SVMID != "svm-1" || engines[0].AverageRate <= 0 {
		t.Fatalf("unexpected engine snapshot: %#v", engines)
	}
	engines[0].NodeName = "ncl1-1-ps-07"
	engines[0].SVMName = "ncl1-1-vs-50"
	engines[0].FPolicy = "connected"
	var output bytes.Buffer
	if err := printEngines(&output, engines); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "SVM") || !strings.Contains(got, "TOTAL EVENTS") || strings.Index(got, "SVM") > strings.Index(got, "NODE") || !strings.Contains(got, "43.1k") || !strings.Contains(got, "connected") || strings.Contains(got, "192.0.2.10") || !strings.Contains(got, "ncl1-1-ps-07") {
		t.Fatalf("unexpected engine table: %s", got)
	}
}

func TestEngineAndFPolicyTablesSortBySVM(t *testing.T) {
	engines := []engineInfo{{SVMName: "zeta", LIFIPv4: "192.0.2.2"}, {SVMName: "Alpha", LIFIPv4: "192.0.2.1"}}
	if err := printEngines(io.Discard, engines); err != nil {
		t.Fatal(err)
	}
	if engines[0].SVMName != "Alpha" {
		t.Fatalf("engines were not sorted by SVM: %#v", engines)
	}
	policies := []fpolicyPolicy{{SVM: "zeta", Name: "one"}, {SVM: "Alpha", Name: "two"}}
	if err := printFPolicyPolicies(io.Discard, policies); err != nil {
		t.Fatal(err)
	}
	if policies[0].SVM != "Alpha" {
		t.Fatalf("policies were not sorted by SVM: %#v", policies)
	}
}

func TestEngineStatusFormatting(t *testing.T) {
	if got := formatFPolicyState("unavailable"); got != text.FgRed.Sprint("off") {
		t.Fatalf("formatFPolicyState(unavailable) = %q", got)
	}
	if got := formatFPolicyState("connected"); got != text.FgGreen.Sprint("connected") {
		t.Fatalf("formatFPolicyState(connected) = %q", got)
	}
	if got := formatLastSeen(time.Time{}); got != text.FgYellow.Sprint("never") {
		t.Fatalf("formatLastSeen(zero) = %q", got)
	}
}

func TestEngineZeroMetricsFormatting(t *testing.T) {
	if formatEventRate(0) != text.FgHiBlack.Sprint("-") || formatEngineEventCount(0) != text.FgHiBlack.Sprint("-") {
		t.Fatal("zero engine metrics were not rendered as muted dashes")
	}
}

func TestFormatMetricGraphCell(t *testing.T) {
	if got := formatMetricGraphCell(5, 10, 6); !strings.Contains(got, "▄▄▄") || !strings.HasSuffix(got, "   ") {
		t.Fatalf("metric graph = %q", got)
	}
	if got := formatMetricGraphCell(0, 10, 6); got != "      " {
		t.Fatalf("zero metric graph = %q", got)
	}
}

func TestFPolicyEngineStatesForServers(t *testing.T) {
	states := fpolicyEngineStatesForServers("node vserver policy-name server server-status\n---- ------- ----------- ------ -------------\nnode-1 finance varonis 192.0.2.20 connected\nnode-1 finance pathdiff 192.0.2.10 disconnected\nnode-2 finance pathdiff 192.0.2.10 connected\n", []string{"192.0.2.10"})
	if states["finance\x00node-1"] != "off" || states["finance\x00node-2"] != "connected" || states["finance\x00node-3"] != "" {
		t.Fatalf("states = %#v", states)
	}
}

func TestFormatEventCount(t *testing.T) {
	if got := formatEventCount(43120); got != "43.1k" {
		t.Fatalf("formatEventCount(43120) = %q", got)
	}
	if got := formatEventCount(1000); got != "1k" {
		t.Fatalf("formatEventCount(1000) = %q", got)
	}
}

func TestPrintMappings(t *testing.T) {
	var output bytes.Buffer
	if err := printMappings(&output, "Volume", "MSID", []store.Mapping{{ID: "2163258291", Name: "asic_user"}}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "VOLUME") || !strings.Contains(got, "asic_user") || !strings.Contains(got, "2163258291") {
		t.Fatalf("unexpected mapping table: %s", got)
	}
}

func TestGenerateCDOTKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "keys", "cdot_ed25519")
	if err := generateCDOTKey(keyFile); err != nil {
		t.Fatal(err)
	}
	publicKey, err := os.ReadFile(keyFile + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(publicKey), "ssh-ed25519 ") {
		t.Fatalf("unexpected public key: %s", publicKey)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(publicKey); err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	privateKey, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		t.Fatal("private key is not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	if err := generateCDOTKey(keyFile); err == nil {
		t.Fatal("generateCDOTKey overwrote an existing key")
	}
}

func TestCDOTCheckHelpers(t *testing.T) {
	if fpolicyPolicyShowCommand != "vserver fpolicy policy show" {
		t.Fatalf("unexpected FPolicy command: %q", fpolicyPolicyShowCommand)
	}
	if fpolicyEngineShowCommand != "vserver fpolicy policy external-engine show -fields primary-servers,secondary-servers,port,ssl-option" {
		t.Fatalf("unexpected external-engine command: %q", fpolicyEngineShowCommand)
	}
	if got := sshAddress("cluster.example.test"); got != "cluster.example.test:22" {
		t.Fatalf("sshAddress() = %q", got)
	}
	if got := sshAddress("192.0.2.10:2222"); got != "192.0.2.10:2222" {
		t.Fatalf("sshAddress() = %q", got)
	}
	if !fpolicyServerMatches("primary-servers: 192.0.2.10", []string{"192.0.2.10"}) {
		t.Fatal("FPolicy endpoint match was not found")
	}
	if fpolicyServerMatches("primary-servers: 192.0.2.10", []string{"192.0.2.11"}) {
		t.Fatal("unexpected FPolicy endpoint match")
	}
}

func TestParseONTAPInstances(t *testing.T) {
	records := parseONTAPInstances("Vserver: finance\nVserver UUID: svm-1\n\nVserver: engineering\nVserver UUID: svm-2\n")
	if len(records) != 2 || instanceField(records[0], "Vserver") != "finance" || instanceField(records[0], "Vserver UUID") != "svm-1" {
		t.Fatalf("unexpected ONTAP records: %#v", records)
	}
}

func TestInstanceFieldUsesLIFVserverName(t *testing.T) {
	if got := instanceField(map[string]string{"Vserver Name": "finance"}, "Vserver"); got != "finance" {
		t.Fatalf("LIF Vserver = %q", got)
	}
}

func TestReachableLIFs(t *testing.T) {
	records := []map[string]string{
		{"Network Address": "172.21.33.154", "Operational Status": "up"},
		{"Network Address": "169.254.82.216", "Operational Status": "up"},
		{"Network Address": "172.21.33.155", "Operational Status": "down"},
		{"Operational Status": "up"},
	}
	filtered := reachableLIFs(records)
	if len(filtered) != 1 || instanceField(filtered[0], "Network Address") != "172.21.33.154" {
		t.Fatalf("reachable LIFs = %#v", filtered)
	}
}

func TestFilterLIFsBySVM(t *testing.T) {
	records := []map[string]string{{"Vserver Name": "ncl1-1-vs-80"}, {"Vserver Name": "ncl1-1-vs-99"}}
	filtered := filterLIFsBySVM(records, "80")
	if len(filtered) != 1 || instanceField(filtered[0], "Vserver") != "ncl1-1-vs-80" {
		t.Fatalf("filtered LIFs = %#v", filtered)
	}
}

func TestFilterLIFs(t *testing.T) {
	records := []map[string]string{
		{"Vserver Name": "ncl1-1-vs-80", "Current Node": "ncl1-1-ps-07", "Subnet Name": "data-80"},
		{"Vserver Name": "ncl1-1-vs-80", "Current Node": "ncl1-1-ps-08", "Subnet Name": "data-80"},
		{"Vserver Name": "ncl1-1-vs-99", "Current Node": "ncl1-1-ps-08", "Subnet Name": "data-99"},
	}
	filtered := filterLIFs(records, "80", "07", "data-80")
	if len(filtered) != 1 || instanceField(filtered[0], "Current Node") != "ncl1-1-ps-07" {
		t.Fatalf("filtered LIFs = %#v", filtered)
	}
}

func TestPrintONTAPRecord(t *testing.T) {
	var output bytes.Buffer
	if err := printONTAPRecord(&output, map[string]string{"Vserver Name": "finance", "Network Address": "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "FIELD") || !strings.Contains(got, "Vserver Name") || !strings.Contains(got, "192.0.2.10") {
		t.Fatalf("unexpected ONTAP record: %s", got)
	}
}

func TestHasONTAPInventoryFields(t *testing.T) {
	if hasONTAPInventoryFields(map[string]string{"Last login time": "now"}, []string{"Node"}) {
		t.Fatal("login banner should not be rendered as inventory")
	}
	if !hasONTAPInventoryFields(map[string]string{"Node": "node-1"}, []string{"Node"}) {
		t.Fatal("node inventory record was excluded")
	}
}

func TestParseONTAPInstancesSkipsLIFLoginBanner(t *testing.T) {
	records := parseONTAPInstances("Last login time: now\n\nVserver Name: finance\nLogical Interface Name: finance_data\nNetwork Address: 192.0.2.10\n")
	var lif map[string]string
	for _, record := range records {
		if instanceField(record, "Logical Interface Name") == "finance_data" {
			lif = record
		}
	}
	if lif == nil || instanceField(lif, "Network Address") != "192.0.2.10" {
		t.Fatalf("LIF record = %#v", lif)
	}
}

func TestParseONTAPVolumeTable(t *testing.T) {
	mappings := parseONTAPVolumeTable("vserver volume msid\n-------- ------ ----\nfinance data 2163258291\nengineering vol0 -\n")
	if len(mappings) != 1 || mappings[0] != (cdotMapping{Vserver: "finance", Name: "data", ID: "2163258291"}) {
		t.Fatalf("unexpected volume mappings: %#v", mappings)
	}
}

func TestParseFPolicyPolicies(t *testing.T) {
	policies := parseFPolicyPolicies("Vserver: finance\nPolicy: track_inode_changes\nEvents to Monitor: inode_change_events\nFPolicy Engine: pathdiff\n", "Vserver: finance\nEngine: pathdiff\nPrimary FPolicy Servers: 192.0.2.10\nSecondary FPolicy Servers: 192.0.2.11\nPort Number of FPolicy Service: 9911\nSSL Option for External Communication: no-auth\nExternal Engine Type: asynchronous\nExternal Engine Format: xml\n")
	if len(policies) != 1 {
		t.Fatalf("policies = %#v", policies)
	}
	policy := policies[0]
	if policy.SVM != "finance" || policy.Name != "track_inode_changes" || policy.Engine != "pathdiff" || policy.Targets != "192.0.2.10, 192.0.2.11" || policy.Port != "9911" || policy.SSL != "no-auth" || policy.Type != "asynchronous" || policy.Format != "xml" || policy.Events != "inode_change_events" {
		t.Fatalf("unexpected policy: %#v", policy)
	}
	applyFPolicyEngineStates(policies, parseFPolicyEngineStates("node vserver policy-name server server-status\n---- ------- ----------- ------ -------------\nnode-1 finance track_inode_changes 192.0.2.10 disconnected\nnode-2 finance track_inode_changes 192.0.2.10 connected\n"))
	if policies[0].State != "connected" {
		t.Fatalf("policy state = %q", policies[0].State)
	}
	if filtered := filterFPolicyPolicies(policies, "finance", "", false); len(filtered) != 1 {
		t.Fatalf("default filter excluded pathdiff policy: %#v", filtered)
	}
}

func TestParseFPolicyScopes(t *testing.T) {
	policies := []fpolicyPolicy{{SVM: "finance", Name: "track_inode_changes", Engine: "pathdiff"}}
	scopes := parseFPolicyScopes("Vserver: finance\nPolicy: track_inode_changes\nVolumes to Exclude: temporary\nVolumes to Include: *\nShares to Exclude: -\nShares to Include: reports\nFile Extensions to Exclude: tmp\nFile Extensions to Include: csv\nExport Policies to Exclude: legacy\nExport Policies to Include: approved\n", policies)
	if len(scopes) != 1 {
		t.Fatalf("scopes = %#v", scopes)
	}
	scope := scopes[0]
	if scope.Engine != "pathdiff" || scope.VolumeExcl != "temporary" || scope.VolumeIncl != "*" || scope.ShareExcl != "-" || scope.ShareIncl != "reports" || scope.ExtensionExcl != "tmp" || scope.ExtensionIncl != "csv" || scope.ExportExcl != "legacy" || scope.ExportIncl != "approved" {
		t.Fatalf("unexpected scope: %#v", scope)
	}
}

func TestFormatFPolicyScopeValue(t *testing.T) {
	if got := formatFPolicyScopeValue("-", text.FgYellow, true); got != text.FgHiBlack.Sprint("-") {
		t.Fatalf("formatFPolicyScopeValue(-) = %q", got)
	}
	if got := formatFPolicyScopeValue("*", text.FgGreen, true); got != text.FgGreen.Sprint("*") {
		t.Fatalf("formatFPolicyScopeValue(*) = %q", got)
	}
	if got := formatFPolicyScopeValue("nfs_os", text.FgYellow, true); got != text.FgYellow.Sprint("nfs_os") {
		t.Fatalf("formatFPolicyScopeValue(nfs_os) = %q", got)
	}
}

func TestFPolicyActionCommands(t *testing.T) {
	fpolicy := newFPolicyCommand()
	for _, name := range []string{"start", "stop"} {
		command, _, err := fpolicy.Find([]string{name})
		if err != nil || command == nil || command.Use != name+" [<svmWildcardSearchTerm> [<policyClass>]]" {
			t.Fatalf("%s command = %#v, err = %v", name, command, err)
		}
		if all, err := command.Flags().GetBool("all"); err != nil || all {
			t.Fatalf("%s --all = %t, err = %v", name, all, err)
		}
	}
}

func TestFPolicySequenceConflict(t *testing.T) {
	if !fpolicySequenceConflict("Error: sequence number 1 is already in use") {
		t.Fatal("expected sequence conflict")
	}
	if fpolicySequenceConflict("Error: permission denied") {
		t.Fatal("unexpected sequence conflict")
	}
}

func TestFPolicyClientLIFs(t *testing.T) {
	lifs := fpolicyClientLIFs([]map[string]string{
		{"Logical Interface Name": "data", "Vserver Name": "finance", "Network Address": "192.0.2.10", "Service List": "data-nfs, data-fpolicy-client", "Operational Status": "up"},
		{"Logical Interface Name": "management", "Vserver Name": "finance", "Network Address": "192.0.2.11", "Service List": "management-ssh", "Operational Status": "up"},
		{"Logical Interface Name": "down", "Vserver Name": "finance", "Network Address": "192.0.2.12", "Service List": "data-fpolicy-client", "Operational Status": "down"},
	})
	if len(lifs) != 1 || lifs[0] != (fpolicyLIF{Name: "data", SVM: "finance", Address: "192.0.2.10"}) {
		t.Fatalf("FPolicy client LIFs = %#v", lifs)
	}
}

func TestFPolicyReachabilityError(t *testing.T) {
	err := &fpolicyReachabilityError{LIF: fpolicyLIF{Name: "data", Address: "192.0.2.10", SVM: "finance", Node: "node-1"}, Reason: "receiver-to-LIF ping also failed, so this LIF is likely on an isolated private network"}
	if got := err.Error(); !strings.Contains(got, "lif=data addr=192.0.2.10 svm=finance node=node-1") || !strings.Contains(got, "isolated private network") {
		t.Fatalf("reachability error = %q", got)
	}
}

func TestFPolicyPingSucceeded(t *testing.T) {
	if !fpolicyPingSucceeded([]byte("1 packets sent, 1 packets were received")) {
		t.Fatal("successful ping was not recognized")
	}
	if fpolicyPingSucceeded([]byte("1 packets sent, 0 packets received, 100% packet loss")) || fpolicyPingSucceeded([]byte("no reply")) {
		t.Fatal("unreachable ping was accepted")
	}
}

func TestParseONTAPInstancesPreservesWrappedServiceList(t *testing.T) {
	records := parseONTAPInstances("Vserver Name: finance\nLogical Interface Name: data\nService List: data-core, data-nfs,\n              data-fpolicy-client\nNetwork Address: 192.0.2.10\nOperational Status: up\n")
	lifs := fpolicyClientLIFs(records)
	if len(lifs) != 1 || !strings.Contains(instanceField(records[0], "Service List"), "data-fpolicy-client") {
		t.Fatalf("wrapped service list was not preserved: %#v", records)
	}
}

func TestONTAPErrorDetail(t *testing.T) {
	detail := ontapErrorDetail([]byte("Last login time: now\n\x1b[1B blob data\nError: The specified server is already\n connected.\n"))
	if detail != "The specified server is already connected." {
		t.Fatalf("ONTAP error detail = %q", detail)
	}
	if !fpolicyAlreadyConnected(detail) {
		t.Fatal("already-connected response was not accepted")
	}
}

func TestFPolicyEngineConnectCommand(t *testing.T) {
	policy := fpolicyPolicy{SVM: "finance", Name: "pathdiff_policy", Targets: "192.0.2.10"}
	if got := "vserver fpolicy engine-connect -vserver " + shellQuote(policy.SVM) + " -policy-name " + shellQuote(policy.Name) + " -node " + shellQuote("node-1") + " -server " + shellQuote("192.0.2.10"); got != "vserver fpolicy engine-connect -vserver \"finance\" -policy-name \"pathdiff_policy\" -node \"node-1\" -server \"192.0.2.10\"" {
		t.Fatalf("engine-connect command = %q", got)
	}
}

func TestFPolicyEngineConnected(t *testing.T) {
	if !fpolicyEngineConnected([]string{"connected", "CONNECTED"}) {
		t.Fatal("expected connected engine states")
	}
	if fpolicyEngineConnected([]string{"connected", "disconnected"}) || fpolicyEngineConnected(nil) {
		t.Fatal("unexpected connected engine states")
	}
}

func TestWaitForFPolicyConnectionHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForFPolicyConnection(ctx, nil, fpolicyPolicy{}, nil, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForFPolicyConnection() error = %v", err)
	}
}

func TestServiceRefreshCommand(t *testing.T) {
	service := newServiceCommand()
	command, _, err := service.Find([]string{"refresh"})
	if err != nil || command == nil || command.Use != "refresh" {
		t.Fatalf("refresh command = %#v, err = %v", command, err)
	}
	if controlPath, err := command.Flags().GetString("control"); err != nil || controlPath != defaultControl {
		t.Fatalf("refresh control path = %q, err = %v", controlPath, err)
	}
}

func TestServiceListPortsCommand(t *testing.T) {
	service := newServiceCommand()
	command, _, err := service.Find([]string{"list-ports"})
	if err != nil || command == nil || command.Use != "list-ports" {
		t.Fatalf("list-ports command = %#v, err = %v", command, err)
	}
	if controlPath, err := command.Flags().GetString("control"); err != nil || controlPath != defaultControl {
		t.Fatalf("list-ports control path = %q, err = %v", controlPath, err)
	}
}

func TestServiceRestartCommand(t *testing.T) {
	service := newServiceCommand()
	command, _, err := service.Find([]string{"restart"})
	if err != nil || command == nil || command.Use != "restart" {
		t.Fatalf("restart command = %#v, err = %v", command, err)
	}
}

func TestFPolicyCreatePlans(t *testing.T) {
	svms := []map[string]string{
		{"Vserver": "finance", "Vserver Type": "data", "Allowed Protocols": "nfs, cifs"},
		{"Vserver": "engineering", "Vserver Type": "data", "Allowed Protocols": "nfs"},
		{"Vserver": "cifs", "Vserver Type": "data", "Allowed Protocols": "cifs"},
		{"Vserver": "admin", "Vserver Type": "admin"},
	}
	policies := []fpolicyPolicy{{SVM: "finance", Name: "pathdiff_policy", Engine: "pathdiff", Port: "9911"}, {SVM: "engineering", Name: "existing_policy", Engine: "other"}}
	sequences := []map[string]string{{"Vserver": "engineering", "Sequence Number": "4"}}
	endpoints := []*net.TCPAddr{{IP: net.ParseIP("192.0.2.10"), Port: 9911}, {IP: net.ParseIP("192.0.2.10"), Port: 9912}, {IP: net.ParseIP("192.0.2.10"), Port: 9913}}
	plans, err := fpolicyCreatePlans(svms, policies, sequences, "*", true, endpoints)
	if err != nil || len(plans) != 1 || plans[0] != (fpolicyCreatePlan{SVM: "engineering", TargetIP: "192.0.2.10", Port: "9912", Sequence: 5}) {
		t.Fatalf("plans = %#v", plans)
	}
	var output bytes.Buffer
	if err := printFPolicyCreateCommands(&output, plans); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "-primary-servers 192.0.2.10 -port 9912") || !strings.Contains(got, "-sequence-number 5") || strings.Contains(got, "finance") {
		t.Fatalf("unexpected create commands: %s", got)
	}
	if err := printFPolicyCreateCommands(errorWriter{}, plans); err == nil || !strings.Contains(err.Error(), "write FPolicy create commands") {
		t.Fatalf("writer error = %v", err)
	}
	fallback, err := fpolicyCreatePlans(svms, policies, nil, "engineering", false, endpoints)
	if err != nil || len(fallback) != 1 || fallback[0].Sequence != 2 {
		t.Fatalf("fallback sequence plans = %#v", fallback)
	}
	explicit, err := fpolicyCreatePlans(svms, policies, nil, "cifs", false, endpoints)
	if err != nil || len(explicit) != 1 || explicit[0].SVM != "cifs" {
		t.Fatalf("explicit non-NFS plans = %#v", explicit)
	}
}

func TestParseListenAddresses(t *testing.T) {
	addresses, err := parseListenAddresses(":9911-9913")
	if err != nil || len(addresses) != 3 || addresses[0].Port != 9911 || addresses[2].Port != 9913 {
		t.Fatalf("addresses = %#v, err = %v", addresses, err)
	}
}

func TestCDOTDefaultClusterConfig(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := setCDOTCluster("cluster.example.test"); err != nil {
		t.Fatal(err)
	}
	config, err := loadCDOTConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Cluster != "cluster.example.test" {
		t.Fatalf("cluster = %q", config.Cluster)
	}
	cdot := newCDOTCommand()
	if host, err := cdot.PersistentFlags().GetString("host"); err != nil || host != "cluster.example.test" {
		t.Fatalf("default cDOT host = %q, err = %v", host, err)
	}
}

func TestCDOTHostKeyCallbackAcceptsNewKey(t *testing.T) {
	knownHostsFile := filepath.Join(t.TempDir(), "known_hosts")
	if _, err := cdotHostKeyCallback(knownHostsFile, "cluster.example.test:22", false); err == nil {
		t.Fatal("strict host key callback accepted a missing known_hosts file")
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	callback, err := cdotHostKeyCallback(knownHostsFile, "cluster.example.test:22", true)
	if err != nil {
		t.Fatal(err)
	}
	remoteAddress := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	if err := callback("cluster.example.test:22", remoteAddress, key); err != nil {
		t.Fatal(err)
	}
	strictCallback, err := cdotHostKeyCallback(knownHostsFile, "cluster.example.test:22", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := strictCallback("cluster.example.test:22", remoteAddress, key); err != nil {
		t.Fatalf("saved host key was not verified: %v", err)
	}
}
