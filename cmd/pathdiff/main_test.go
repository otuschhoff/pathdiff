package main

import (
	"bufio"
	"net"
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
