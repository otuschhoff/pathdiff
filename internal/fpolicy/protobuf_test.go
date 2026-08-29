package fpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
	payload := []byte(`<FPolicy xmlns="http://www.netapp.com/fpolicy"><Header><SessionID>sess-1</SessionID></Header><NotificationRequest><Vserver>vs-1</Vserver><FileId>42</FileId><VolumeUuid>vol-1</VolumeUuid><Path>/vol/data/report.csv</Path><Operation>WRITE</Operation><Timestamp>1725000000000000</Timestamp></NotificationRequest></FPolicy>`)
	event, err := ParseXMLNotification(payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.Inode != 42 || event.Path != "/vol/data/report.csv" || event.Operation != "WRITE" {
		t.Fatalf("unexpected event: %#v", event)
	}
	if want := time.UnixMicro(1_725_000_000_000_000).UTC(); !event.Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", event.Timestamp, want)
	}
}

func TestNegotiateResponse(t *testing.T) {
	payload, err := NegotiateResponse("sess-998811")
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<FPolicy xmlns=\"http://www.netapp.com/fpolicy\"><Header><SessionID>sess-998811</SessionID></Header><NegotiateResponse><SelectedProtocol>1.0</SelectedProtocol><Status>SUCCESS</Status></NegotiateResponse></FPolicy>" {
		t.Fatalf("unexpected handshake response: %s", payload)
	}
}

func TestONTAPXMLHandshakeFrames(t *testing.T) {
	request := []byte(`<?xml version="1.0"?><Handshake><VsUUID>5b701784-7459-11e8-8e95-00a098bc5a13</VsUUID><PolicyName>track_inode_changes</PolicyName><SessionId>bef098d2-a3a6-11f1-8e8e-d039ea524d0f</SessionId><ProtVersion><Vers>1.0</Vers><Vers>1.1</Vers></ProtVersion></Handshake>`)
	var wire bytes.Buffer
	writeCapturedONTAPFrame(&wire, "NEGO_REQ", request)
	message, err := ReadONTAPXMLFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != "NEGO_REQ" || message.Session != "bef098d2-a3a6-11f1-8e8e-d039ea524d0f" || message.VserverUUID != "5b701784-7459-11e8-8e95-00a098bc5a13" || message.PolicyName != "track_inode_changes" {
		t.Fatalf("unexpected handshake: %#v", message)
	}

	response, err := ONTAPNegotiateResponse(message.Session, message.VserverUUID, message.PolicyName)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteONTAPXMLFrame(&wire, "NEGO_RESP", response); err != nil {
		t.Fatal(err)
	}
	responseWire := wire.Bytes()
	if responseWire[0] != ontapXMLMessageType || responseWire[5] != ontapXMLMessageType || int(binary.BigEndian.Uint32(responseWire[1:5])) != len(responseWire)-6 || !bytes.Contains(responseWire, []byte(`<?xml version="1.0"?>`)) || !bytes.Contains(responseWire, []byte("<HandshakeResp><VsUUID>5b701784-7459-11e8-8e95-00a098bc5a13</VsUUID><PolicyName>track_inode_changes</PolicyName><SessionId>bef098d2-a3a6-11f1-8e8e-d039ea524d0f</SessionId><ProtVersion>1.2</ProtVersion></HandshakeResp>")) {
		t.Fatalf("unexpected negotiation response: %q", responseWire)
	}
}

func TestONTAPKeepAliveFrame(t *testing.T) {
	var wire bytes.Buffer
	writeCapturedONTAPFrame(&wire, "KEEP_ALIVE", nil)
	message, err := ReadONTAPXMLFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != "KEEP_ALIVE" || len(message.Payload) != 0 {
		t.Fatalf("unexpected keep-alive message: %#v", message)
	}
}

func writeCapturedONTAPFrame(writer *bytes.Buffer, notificationType string, payload []byte) {
	header := fmt.Sprintf(`<?xml version="1.0"?><Header><NotfType>%s</NotfType><ContentLen>%d</ContentLen><DataFormat>XML</DataFormat></Header>`, notificationType, len(payload))
	framePayload := append([]byte{ontapXMLMessageType}, header...)
	framePayload = append(framePayload, '\n', '\n')
	framePayload = append(framePayload, payload...)
	_ = writer.WriteByte(ontapXMLMessageType)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(framePayload)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(framePayload)
	_ = writer.WriteByte(0)
}
