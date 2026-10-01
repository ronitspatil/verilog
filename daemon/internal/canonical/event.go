package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/sha3"
)

// TimestampLayout is the canonical form of timestamp_utc: RFC 3339 in UTC
// with exactly nine fractional digits, so equal instants hash identically.
const TimestampLayout = "2006-01-02T15:04:05.000000000Z"

// Field limits enforced on every event.
const (
	MaxAgentIDBytes   = 256
	MaxEventTypeBytes = 128
)

// ErrInvalidEvent is wrapped by every event validation error.
var ErrInvalidEvent = errors.New("invalid event")

// Event is the hashed content of one log event.
type Event struct {
	AgentID      string
	StepNumber   uint64
	EventType    string
	PayloadJSON  []byte // any valid JSON document
	TimestampUTC time.Time
}

// Validate checks the field rules shared by ingestion and verification.
func (e Event) Validate() error {
	switch {
	case e.AgentID == "":
		return fmt.Errorf("%w: agent_id is empty", ErrInvalidEvent)
	case len(e.AgentID) > MaxAgentIDBytes:
		return fmt.Errorf("%w: agent_id longer than %d bytes", ErrInvalidEvent, MaxAgentIDBytes)
	case !utf8.ValidString(e.AgentID):
		return fmt.Errorf("%w: agent_id is not valid UTF-8", ErrInvalidEvent)
	case e.EventType == "":
		return fmt.Errorf("%w: event_type is empty", ErrInvalidEvent)
	case len(e.EventType) > MaxEventTypeBytes:
		return fmt.Errorf("%w: event_type longer than %d bytes", ErrInvalidEvent, MaxEventTypeBytes)
	case !utf8.ValidString(e.EventType):
		return fmt.Errorf("%w: event_type is not valid UTF-8", ErrInvalidEvent)
	case e.TimestampUTC.IsZero():
		return fmt.Errorf("%w: timestamp_utc is missing", ErrInvalidEvent)
	case len(e.PayloadJSON) == 0:
		return fmt.Errorf("%w: payload_json is empty", ErrInvalidEvent)
	}
	return nil
}

// Canonical returns the canonical JSON bytes of the event:
//
//	{"agent_id":…,"event_type":…,"payload":<canonical payload>,"step_number":…,"timestamp_utc":…}
func (e Event) Canonical() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	payload, err := parse(e.PayloadJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: payload_json: %v", ErrInvalidEvent, err)
	}
	doc := object{
		{key: "agent_id", value: e.AgentID},
		{key: "event_type", value: e.EventType},
		{key: "payload", value: payload},
		{key: "step_number", value: e.StepNumber},
		{key: "timestamp_utc", value: e.TimestampUTC.UTC().Format(TimestampLayout)},
	}
	var buf bytes.Buffer
	buf.Grow(len(e.PayloadJSON) + 160)
	if err := encode(&buf, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseEvent strictly decodes an event JSON document (as written in evidence
// bundles and exported event.json files). The document must have exactly the
// five canonical fields; member order and whitespace are free.
func ParseEvent(doc []byte) (Event, error) {
	v, err := parse(doc)
	if err != nil {
		return Event{}, err
	}
	obj, ok := v.(object)
	if !ok {
		return Event{}, fmt.Errorf("%w: event is not a JSON object", ErrInvalidEvent)
	}
	fields := map[string]any{}
	for _, m := range obj {
		fields[m.key] = m.value
	}
	want := []string{"agent_id", "event_type", "payload", "step_number", "timestamp_utc"}
	if len(fields) != len(want) {
		return Event{}, fmt.Errorf("%w: event must have exactly the fields %s", ErrInvalidEvent, strings.Join(want, ", "))
	}
	for _, k := range want {
		if _, ok := fields[k]; !ok {
			return Event{}, fmt.Errorf("%w: missing field %q", ErrInvalidEvent, k)
		}
	}

	var ev Event
	if ev.AgentID, ok = fields["agent_id"].(string); !ok {
		return Event{}, fmt.Errorf("%w: agent_id must be a string", ErrInvalidEvent)
	}
	if ev.EventType, ok = fields["event_type"].(string); !ok {
		return Event{}, fmt.Errorf("%w: event_type must be a string", ErrInvalidEvent)
	}
	num, ok := fields["step_number"].(json.Number)
	if !ok {
		return Event{}, fmt.Errorf("%w: step_number must be a number", ErrInvalidEvent)
	}
	if ev.StepNumber, err = strconv.ParseUint(string(num), 10, 64); err != nil {
		return Event{}, fmt.Errorf("%w: step_number must be a non-negative 64-bit integer", ErrInvalidEvent)
	}
	ts, ok := fields["timestamp_utc"].(string)
	if !ok {
		return Event{}, fmt.Errorf("%w: timestamp_utc must be a string", ErrInvalidEvent)
	}
	if ev.TimestampUTC, err = time.Parse(TimestampLayout, ts); err != nil {
		return Event{}, fmt.Errorf("%w: timestamp_utc must have the form %s", ErrInvalidEvent, TimestampLayout)
	}
	var pbuf bytes.Buffer
	if err := encode(&pbuf, fields["payload"]); err != nil {
		return Event{}, err
	}
	ev.PayloadJSON = pbuf.Bytes()
	return ev, ev.Validate()
}

// Digest is a 32-byte hash.
type Digest [32]byte

// Hex returns the 0x-prefixed lowercase hex encoding.
func (d Digest) Hex() string { return "0x" + hex.EncodeToString(d[:]) }

// ContentDigest is SHA-256 over canonical event bytes.
func ContentDigest(canonicalEvent []byte) Digest {
	return sha256.Sum256(canonicalEvent)
}

// AgentKey is the on-chain agent identifier: keccak256(utf8(agentID)).
func AgentKey(agentID string) Digest {
	return Keccak256([]byte(agentID))
}

// Keccak256 is the Ethereum (pre-standard) Keccak-256 hash.
func Keccak256(data ...[]byte) Digest {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	var out Digest
	h.Sum(out[:0])
	return out
}

// ParseDigest decodes a 0x-prefixed (or bare) 64-character hex string.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 64 {
		return d, fmt.Errorf("expected 32-byte hex value, got %d hex characters", len(s))
	}
	if _, err := hex.Decode(d[:], []byte(s)); err != nil {
		return d, fmt.Errorf("invalid hex: %v", err)
	}
	return d, nil
}
