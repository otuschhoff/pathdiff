package fpolicy

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"pathdiff/internal/store"
)

const MaxFrameSize = 1024 * 1024

const ontapXMLMessageType = 0x22

type ONTAPMessage struct {
	Type        string
	Session     string
	VserverUUID string
	PolicyName  string
	Payload     []byte
}

// ReadONTAPXMLFrame reads the FPolicy frame seen on the ONTAP wire: a one-byte
// message type, a big-endian payload length, an XML header/body payload, and NUL.
func ReadONTAPXMLFrame(reader io.Reader) (ONTAPMessage, error) {
	messageType, err := readByte(reader)
	if err != nil {
		return ONTAPMessage{}, err
	}
	if messageType != ontapXMLMessageType {
		return ONTAPMessage{}, fmt.Errorf("unsupported ONTAP message type %#x", messageType)
	}
	payload, err := readSizedPayload(reader)
	if err != nil {
		return ONTAPMessage{}, err
	}
	if _, err := readByte(reader); err != nil {
		return ONTAPMessage{}, err
	}

	parts := bytes.SplitN(bytes.TrimPrefix(payload, []byte{'"'}), []byte("\n\n"), 2)
	var header struct {
		NotificationType string `xml:"NotfType"`
	}
	if err := xml.Unmarshal(parts[0], &header); err != nil {
		return ONTAPMessage{}, fmt.Errorf("decode ONTAP XML header: %w", err)
	}
	message := ONTAPMessage{Type: header.NotificationType}
	if len(parts) == 2 {
		message.Payload = bytes.TrimSpace(parts[1])
	}
	if message.Type == "NEGO_REQ" {
		if len(message.Payload) == 0 {
			return ONTAPMessage{}, fmt.Errorf("missing ONTAP negotiation payload")
		}
		var handshake struct {
			VserverUUID string `xml:"VsUUID"`
			PolicyName  string `xml:"PolicyName"`
			Session     string `xml:"SessionId"`
		}
		if err := xml.Unmarshal(message.Payload, &handshake); err != nil {
			return ONTAPMessage{}, fmt.Errorf("decode ONTAP handshake: %w", err)
		}
		message.Session = handshake.Session
		message.VserverUUID = handshake.VserverUUID
		message.PolicyName = handshake.PolicyName
	}
	return message, nil
}

func WriteONTAPXMLFrame(writer io.Writer, notificationType string, payload []byte) error {
	header := fmt.Sprintf(`<?xml version="1.0"?><Header><NotfType>%s</NotfType><ContentLen>%d</ContentLen><DataFormat>XML</DataFormat></Header>`, notificationType, len(payload))
	framePayload := append([]byte(header+"\n\n"), payload...)
	if len(framePayload) > MaxFrameSize {
		return fmt.Errorf("frame length %d exceeds %d bytes", len(framePayload), MaxFrameSize)
	}
	if _, err := writer.Write([]byte{ontapXMLMessageType}); err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(framePayload)))
	if _, err := writer.Write(length[:]); err != nil {
		return err
	}
	if _, err := writer.Write([]byte{ontapXMLMessageType}); err != nil {
		return err
	}
	_, err := writer.Write(framePayload)
	return err
}

func ONTAPNegotiateResponse(session, vserverUUID, policyName string) ([]byte, error) {
	response := struct {
		XMLName     xml.Name `xml:"HandshakeResp"`
		VserverUUID string   `xml:"VsUUID"`
		PolicyName  string   `xml:"PolicyName"`
		Session     string   `xml:"SessionId"`
		Version     string   `xml:"ProtVersion"`
	}{VserverUUID: vserverUUID, PolicyName: policyName, Session: session, Version: "1.2"}
	payload, err := xml.Marshal(response)
	if err != nil {
		return nil, err
	}
	return append([]byte(`<?xml version="1.0"?>`), payload...), nil
}

func readByte(reader io.Reader) (byte, error) {
	var value [1]byte
	_, err := io.ReadFull(reader, value[:])
	return value[0], err
}

func readSizedPayload(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > MaxFrameSize {
		return nil, fmt.Errorf("frame length %d exceeds %d bytes", length, MaxFrameSize)
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

// ParseXMLNotification decodes an XML notification using the field names in the
// FPolicy event schema. Both XML elements and attributes are accepted.
func ParseXMLNotification(payload []byte) (store.Event, error) {
	message, err := ParseXMLMessage(payload)
	if err != nil {
		return store.Event{}, err
	}
	if message.Notification == nil {
		return store.Event{}, fmt.Errorf("expected NotificationRequest")
	}
	return *message.Notification, nil
}

type XMLMessage struct {
	SessionID    string
	Negotiate    bool
	Notification *store.Event
}

type xmlEnvelope struct {
	Header struct {
		SessionID string `xml:"SessionID"`
	} `xml:"Header"`
	NegotiateRequest    *struct{} `xml:"NegotiateRequest"`
	NotificationRequest *struct {
		Vserver    string `xml:"Vserver"`
		FileID     uint64 `xml:"FileId"`
		VolumeUUID string `xml:"VolumeUuid"`
		Path       string `xml:"Path"`
		Operation  string `xml:"Operation"`
		Timestamp  int64  `xml:"Timestamp"`
	} `xml:"NotificationRequest"`
}

// ParseXMLMessage decodes the documented FPolicy XML envelope and payloads.
func ParseXMLMessage(payload []byte) (XMLMessage, error) {
	var envelope xmlEnvelope
	if err := xml.Unmarshal(payload, &envelope); err != nil {
		return XMLMessage{}, err
	}
	message := XMLMessage{SessionID: envelope.Header.SessionID}
	if envelope.NegotiateRequest != nil {
		message.Negotiate = true
		return message, nil
	}
	if notification := envelope.NotificationRequest; notification != nil {
		if notification.Path == "" {
			return XMLMessage{}, fmt.Errorf("notification path is required")
		}
		message.Notification = &store.Event{
			Inode:      notification.FileID,
			Path:       notification.Path,
			Operation:  notification.Operation,
			Timestamp:  time.UnixMicro(notification.Timestamp).UTC(),
			Vserver:    notification.Vserver,
			VolumeUUID: notification.VolumeUUID,
		}
		return message, nil
	}
	return XMLMessage{}, fmt.Errorf("unknown FPolicy XML message")
}

func NegotiateResponse(sessionID string) ([]byte, error) {
	response := struct {
		XMLName xml.Name `xml:"FPolicy"`
		XMLNS   string   `xml:"xmlns,attr"`
		Header  struct {
			SessionID string `xml:"SessionID"`
		} `xml:"Header"`
		NegotiateResponse struct {
			SelectedProtocol string `xml:"SelectedProtocol"`
			Status           string `xml:"Status"`
		} `xml:"NegotiateResponse"`
	}{XMLNS: "http://www.netapp.com/fpolicy"}
	response.Header.SessionID = sessionID
	response.NegotiateResponse.SelectedProtocol = "1.0"
	response.NegotiateResponse.Status = "SUCCESS"
	payload, err := xml.Marshal(response)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), payload...), nil
}

func decodeLegacyXMLNotification(payload []byte) (store.Event, error) {
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	return DecodeXMLNotification(decoder)
}

// DecodeXMLNotification reads one XML notification from a stream.
func DecodeXMLNotification(decoder *xml.Decoder) (store.Event, error) {
	var event store.Event
	var elements []string
	inNotification := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if inNotification {
				return store.Event{}, io.ErrUnexpectedEOF
			}
			return store.Event{}, io.EOF
		}
		if err != nil {
			return store.Event{}, err
		}
		switch token := token.(type) {
		case xml.StartElement:
			inNotification = true
			elements = append(elements, token.Name.Local)
			for _, attribute := range token.Attr {
				if err := setXMLField(&event, attribute.Name.Local, attribute.Value); err != nil {
					return store.Event{}, err
				}
			}
		case xml.CharData:
			if len(elements) > 0 {
				if err := setXMLField(&event, elements[len(elements)-1], string(token)); err != nil {
					return store.Event{}, err
				}
			}
		case xml.EndElement:
			if len(elements) == 0 {
				return store.Event{}, fmt.Errorf("unexpected closing XML element %q", token.Name.Local)
			}
			elements = elements[:len(elements)-1]
			if len(elements) != 0 {
				continue
			}
			if event.Path == "" {
				return store.Event{}, fmt.Errorf("notification path is required")
			}
			return event, nil
		}
	}
}

func setXMLField(event *store.Event, name, value string) error {
	value = strings.TrimSpace(value)
	switch strings.ToLower(strings.ReplaceAll(name, "-", "_")) {
	case "file_id", "inode":
		if value == "" {
			return nil
		}
		inode, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse inode: %w", err)
		}
		event.Inode = inode
	case "path":
		event.Path = value
	case "operation":
		event.Operation = strings.ToLower(value)
	case "timestamp_nsec":
		if value == "" {
			return nil
		}
		timestamp, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("parse timestamp_nsec: %w", err)
		}
		event.Timestamp = time.Unix(0, timestamp).UTC()
	}
	return nil
}
