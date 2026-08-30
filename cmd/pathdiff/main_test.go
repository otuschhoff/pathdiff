package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pathdiff/internal/store"

	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/crypto/ssh"
)

func TestFPolicyListenerManagerPorts(t *testing.T) {
	manager := &fpolicyListenerManager{listeners: map[int]*managedFPolicyListener{
		9912: {svms: []string{"svm-two"}, sources: map[string]struct{}{"192.0.2.11": {}, "192.0.2.10": {}}},
		9911: {svms: []string{"svm-one"}, sources: map[string]struct{}{"192.0.2.12": {}}},
	}}
	manager.snapshotPortsLocked()
	ports := manager.Ports()
	if len(ports) != 2 || ports[0].Port != 9911 || ports[1].Port != 9912 || strings.Join(ports[1].SVMs, ",") != "svm-two" || strings.Join(ports[1].Sources, ",") != "192.0.2.10,192.0.2.11" {
		t.Fatalf("ports = %#v", ports)
	}
}

func TestSameSourcesAllowsEmptySourceSets(t *testing.T) {
	if !sameSources(map[string]struct{}{}, map[string]struct{}{}) {
		t.Fatal("empty source sets should be equal")
	}
}

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

func TestPrintParentPathsCoalescesDirectories(t *testing.T) {
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	events := []store.Event{
		{Path: "/vol/alpha/a.txt", Timestamp: base, VolumeName: "one"},
		{Path: "/vol/alpha/b.txt", Timestamp: base.Add(time.Minute), VolumeName: "one"},
		{Path: "/vol/alpha/a.txt", Timestamp: base.Add(2 * time.Minute), VolumeName: "one"},
		{Path: "/vol/beta/c.txt", Timestamp: base, VolumeName: "one"},
	}
	var output bytes.Buffer
	if err := printParentPaths(&output, events, "*", 100, "path"); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Count(got, "/vol/alpha") != 1 || strings.Count(got, "/vol/beta") != 1 || !strings.Contains(got, "2026-08-29T12:02:00Z") || !strings.Contains(got, "CNT") {
		t.Fatalf("parent paths were not coalesced to latest changes: %s", got)
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

func TestEngineSnapshotAndFormatting(t *testing.T) {
	tracker := newSenderTracker(false)
	tracker.senders["192.0.2.10"] = &senderStats{
		active:         1,
		connectedSince: time.Now().UTC().Add(-time.Minute),
		totalEvents:    43120,
		localPort:      "9911",
		lastSeen:       time.Now().UTC().Add(-time.Minute),
		nodeID:         "node-1",
		svmID:          "svm-1",
	}
	engines := tracker.engines()
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

func TestSenderTrackerRequestRate(t *testing.T) {
	tracker := newSenderTracker(false)
	tracker.startedAt = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	tracker.senders["192.0.2.10"] = &senderStats{totalEvents: 90}
	tracker.senders["192.0.2.11"] = &senderStats{totalEvents: 30}
	if got := tracker.requestRate(tracker.startedAt.Add(2 * time.Minute)); got != 1 {
		t.Fatalf("requestRate() = %f, want 1", got)
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
