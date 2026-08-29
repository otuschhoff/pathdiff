package fpolicy

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestParseNotification(t *testing.T) {
	header := protowire.AppendTag(nil, 2, protowire.VarintType)
	header = protowire.AppendVarint(header, uint64(1_725_000_000_000_000_000))
	payload := protowire.AppendTag(nil, 1, protowire.BytesType)
	payload = protowire.AppendBytes(payload, header)
	payload = protowire.AppendTag(payload, 2, protowire.VarintType)
	payload = protowire.AppendVarint(payload, 42)
	payload = protowire.AppendTag(payload, 4, protowire.BytesType)
	payload = protowire.AppendString(payload, "/vol/data/report.csv")
	payload = protowire.AppendTag(payload, 5, protowire.VarintType)
	payload = protowire.AppendVarint(payload, 3)

	event, err := ParseNotification(payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.Inode != 42 || event.Path != "/vol/data/report.csv" || event.Operation != "write" {
		t.Fatalf("unexpected event: %#v", event)
	}
	if want := time.Unix(0, 1_725_000_000_000_000_000).UTC(); !event.Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", event.Timestamp, want)
	}
}

func TestFrames(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	payload, err := ReadFrame(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte{1, 2, 3}) {
		t.Fatalf("payload = %v", payload)
	}
}

func TestParseXMLNotification(t *testing.T) {
	payload := []byte(`<FileOperationNotification><Header timestamp_nsec="1725000000000000000"/><file_id>42</file_id><path>/vol/data/report.csv</path><operation>WRITE</operation></FileOperationNotification>`)
	event, err := ParseXMLNotification(payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.Inode != 42 || event.Path != "/vol/data/report.csv" || event.Operation != "write" {
		t.Fatalf("unexpected event: %#v", event)
	}
	if want := time.Unix(0, 1_725_000_000_000_000_000).UTC(); !event.Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", event.Timestamp, want)
	}
}
