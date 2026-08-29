package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pathdiff/internal/store"
)

func TestTrafficRecorder(t *testing.T) {
	server, client := net.Pipe()
	recorder, err := newTrafficRecorder(server, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("request"))
		done <- err
	}()
	buffer := make([]byte, len("request"))
	if _, err := recorder.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	done = make(chan error, 1)
	go func() {
		buffer := make([]byte, len("response"))
		_, err := client.Read(buffer)
		done <- err
	}()
	if _, err := recorder.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	inFiles, err := filepath.Glob(filepath.Join(filepath.Dir(recorder.in.Name()), "*.in"))
	if err != nil || len(inFiles) != 1 {
		t.Fatalf("in capture files = %v, err = %v", inFiles, err)
	}
	outFiles, err := filepath.Glob(filepath.Join(filepath.Dir(recorder.out.Name()), "*.out"))
	if err != nil || len(outFiles) != 1 {
		t.Fatalf("out capture files = %v, err = %v", outFiles, err)
	}
	in, err := os.ReadFile(inFiles[0])
	if err != nil || string(in) != "request" {
		t.Fatalf("in capture = %q, err = %v", in, err)
	}
	out, err := os.ReadFile(outFiles[0])
	if err != nil || string(out) != "response" {
		t.Fatalf("out capture = %q, err = %v", out, err)
	}
}

func TestConnectionRegistryCloseAll(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	registry := newConnectionRegistry()
	registry.Add(server)
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := server.Read(buffer)
		done <- err
	}()

	registry.CloseAll()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reader returned no error after registry shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("registry shutdown did not unblock the connection reader")
	}
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
	if got := output.String(); !strings.Contains(got, "2 results match") || !strings.Contains(got, "increase --max") {
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
	if got := output.String(); !strings.Contains(got, "2 changed paths match") {
		t.Fatalf("unexpected path limit output: %s", got)
	}
}
