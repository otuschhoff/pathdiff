package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pathdiff/internal/fpolicy"
	"pathdiff/internal/store"
)

func TestFramedXMLSession(t *testing.T) {
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	done := make(chan struct{})
	go func() {
		readFramedEvents(bufio.NewReader(server), server, db)
		close(done)
	}()

	handshake := []byte(`<?xml version="1.0"?><FPolicy xmlns="http://www.netapp.com/fpolicy"><Header><SessionID>sess-998811</SessionID></Header><NegotiateRequest><VserverUuid>vs-uuid-123</VserverUuid></NegotiateRequest></FPolicy>`)
	if err := fpolicy.WriteFrame(client, handshake); err != nil {
		t.Fatal(err)
	}
	response, err := fpolicy.ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"<SessionID>sess-998811</SessionID>", "<SelectedProtocol>1.0</SelectedProtocol>", "<Status>SUCCESS</Status>"} {
		if !strings.Contains(string(response), field) {
			t.Fatalf("negotiation response is missing %s: %s", field, response)
		}
	}

	notification := []byte(`<FPolicy xmlns="http://www.netapp.com/fpolicy"><Header><SeqNum>5001</SeqNum><SessionID>sess-998811</SessionID></Header><NotificationRequest><Vserver>ncl1-1-vs-50</Vserver><FileId>1048576</FileId><VolumeUuid>98765432-abcd-ef01-2345-6789abcdef01</VolumeUuid><Path>/vol/data/engineering/main.go</Path><Operation>WRITE</Operation><Timestamp>1724937927000000</Timestamp></NotificationRequest></FPolicy>`)
	if err := fpolicy.WriteFrame(client, notification); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	<-done

	events, err := db.EventsSince(time.UnixMicro(1_724_937_927_000_000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Inode != 1_048_576 || events[0].Vserver != "ncl1-1-vs-50" || events[0].VolumeUUID != "98765432-abcd-ef01-2345-6789abcdef01" {
		t.Fatalf("stored events = %#v", events)
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
