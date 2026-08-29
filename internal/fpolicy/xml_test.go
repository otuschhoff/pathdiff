package fpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func TestParseXMLNotification(t *testing.T) {
	payload := []byte(`<FPolicy xmlns="http://www.netapp.com/fpolicy"><Header><SessionID>sess-1</SessionID></Header><NotificationRequest><Path>/vol/data/report.csv</Path><Operation>WRITE</Operation><Timestamp>1725000000000000</Timestamp></NotificationRequest></FPolicy>`)
	event, err := ParseXMLNotification(payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.Path != "/vol/data/report.csv" || event.Operation != "WRITE" {
		t.Fatalf("unexpected event: %#v", event)
	}
	if want := time.UnixMicro(1_725_000_000_000_000).UTC(); !event.Timestamp.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", event.Timestamp, want)
	}
}

func TestParseScreenRequest(t *testing.T) {
	payload := []byte(`<FscreenReq><ReqId>211090950</ReqId><ReqType>NFS_WR</ReqType><NotfInfo><NfsWrReq><CommonInfo><ProtCommonInfo><GenerationTime>1788009794015352</GenerationTime><AccessPath><Path><PathNameType>WIN_NAME</PathNameType><PathName>\cache\entry</PathName></Path><Path><PathNameType>UNIX_NAME</PathNameType><PathName>/cache/entry</PathName></Path></AccessPath><VolMsid>2163258291</VolMsid></ProtCommonInfo></CommonInfo></NfsWrReq></NotfInfo></FscreenReq>`)
	event, err := ParseScreenRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.Path != "/cache/entry" || event.Operation != "NFS_WR" {
		t.Fatalf("unexpected screen event: %#v", event)
	}
	if want := time.UnixMicro(1_788_009_794_015_352).UTC(); !event.Timestamp.Equal(want) {
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
