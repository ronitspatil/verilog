package canonical

import (
	"bytes"
	"crypto/ed25519"
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

// SigningDomain prefixes the bytes an agent signs, so an agent key can never
// be tricked into signing something that is also a valid message elsewhere.
const SigningDomain = "VeriLog/event/v1\n"

// Field limits enforced on every event.
const (
	MaxAgentIDBytes   = 256
	MaxEventTypeBytes = 128
	MaxRunIDBytes     = 256
)

// Event types emitted by the SDK itself (not by agent callbacks).
const (
	// EventRunEnd is the terminal event of a run: {"steps":n,"status":"..."}.
	EventRunEnd = "run_end"
	// EventSDKDropped reports events the SDK dropped before they were
	// chained: {"count":n}.
	EventSDKDropped = "sdk_dropped"
)

// ErrInvalidEvent is wrapped by every event validation error.
var ErrInvalidEvent = errors.New("invalid event")

// ErrBadSignature is returned by VerifySig when the signature does not verify.
var ErrBadSignature = errors.New("invalid event signature")

// Event is the hashed content of one log event (canonical event v2).
//
// The canonical JSON has exactly nine members, sorted:
//
//	agent_id, event_type, key_id, payload, prev_hash, run_id, sig, step_number, timestamp_utc
//
// key_id, prev_hash and sig are 0x-prefixed lowercase hex strings. The agent
// signs SigningDomain || canonical(event without "sig") with Ed25519, and the
// content digest covers the event including "sig".
type Event struct {
	AgentID      string
	RunID        string
	StepNumber   uint64
	PrevHash     Digest // content digest of the previous event of the run; zero for genesis
	EventType    string
	PayloadJSON  []byte // any valid JSON document
	TimestampUTC time.Time
	KeyID        Digest // keccak256(ed25519 public key)
	Sig          []byte // ed25519 signature over SigningBytes()
}

// Validate checks the field rules shared by ingestion and verification.
func (e Event) Validate() error {
	if err := e.validateUnsigned(); err != nil {
		return err
	}
	if len(e.Sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: sig must be %d bytes, got %d", ErrInvalidEvent, ed25519.SignatureSize, len(e.Sig))
	}
	return nil
}

func (e Event) validateUnsigned() error {
	switch {
	case e.AgentID == "":
		return fmt.Errorf("%w: agent_id is empty", ErrInvalidEvent)
	case len(e.AgentID) > MaxAgentIDBytes:
		return fmt.Errorf("%w: agent_id longer than %d bytes", ErrInvalidEvent, MaxAgentIDBytes)
	case !utf8.ValidString(e.AgentID):
		return fmt.Errorf("%w: agent_id is not valid UTF-8", ErrInvalidEvent)
	case e.RunID == "":
		return fmt.Errorf("%w: run_id is empty", ErrInvalidEvent)
	case len(e.RunID) > MaxRunIDBytes:
		return fmt.Errorf("%w: run_id longer than %d bytes", ErrInvalidEvent, MaxRunIDBytes)
	case !utf8.ValidString(e.RunID):
		return fmt.Errorf("%w: run_id is not valid UTF-8", ErrInvalidEvent)
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
	case e.KeyID == Digest{}:
		return fmt.Errorf("%w: key_id is missing", ErrInvalidEvent)
	}
	return nil
}

// encodeDoc writes the canonical JSON, with or without the "sig" member.
func (e Event) encodeDoc(withSig bool) ([]byte, error) {
	payload, err := parse(e.PayloadJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: payload_json: %v", ErrInvalidEvent, err)
	}
	doc := object{
		{key: "agent_id", value: e.AgentID},
		{key: "event_type", value: e.EventType},
		{key: "key_id", value: e.KeyID.Hex()},
		{key: "payload", value: payload},
		{key: "prev_hash", value: e.PrevHash.Hex()},
		{key: "run_id", value: e.RunID},
		{key: "step_number", value: e.StepNumber},
		{key: "timestamp_utc", value: e.TimestampUTC.UTC().Format(TimestampLayout)},
	}
	if withSig {
		doc = append(doc, member{key: "sig", value: "0x" + hex.EncodeToString(e.Sig)})
	}
	var buf bytes.Buffer
	buf.Grow(len(e.PayloadJSON) + 512)
	if err := encode(&buf, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Canonical returns the canonical JSON bytes of the signed event (all nine
// fields). These are the bytes the content digest is computed over.
func (e Event) Canonical() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e.encodeDoc(true)
}

// SigningBytes returns SigningDomain || canonical(event without "sig"),
// the message the agent signs. Sig is ignored and may be empty.
func (e Event) SigningBytes() ([]byte, error) {
	if err := e.validateUnsigned(); err != nil {
		return nil, err
	}
	body, err := e.encodeDoc(false)
	if err != nil {
		return nil, err
	}
	return append([]byte(SigningDomain), body...), nil
}

// Sign sets KeyID to the key id of priv's public key and Sig to the
// Ed25519 signature over SigningBytes().
func (e *Event) Sign(priv ed25519.PrivateKey) error {
	e.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	msg, err := e.SigningBytes()
	if err != nil {
		return err
	}
	e.Sig = ed25519.Sign(priv, msg)
	return nil
}

// VerifySig checks that pub matches KeyID and that Sig is a valid Ed25519
// signature by pub over SigningBytes(). Errors wrap ErrBadSignature or
// ErrInvalidEvent.
func (e Event) VerifySig(pub ed25519.PublicKey) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key must be %d bytes", ErrBadSignature, ed25519.PublicKeySize)
	}
	if KeyID(pub) != e.KeyID {
		return fmt.Errorf("%w: public key does not match key_id %s", ErrBadSignature, e.KeyID.Hex())
	}
	msg, err := e.SigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, e.Sig) {
		return ErrBadSignature
	}
	return nil
}

// KeyID is the on-chain key identifier of an Ed25519 public key:
// keccak256(pubkey), the same value VeriLogRegistry.registerAgentKey returns.
func KeyID(pub ed25519.PublicKey) Digest {
	return Keccak256(pub)
}

// eventFields are the members of a canonical v2 event.
var eventFields = []string{"agent_id", "event_type", "key_id", "payload", "prev_hash", "run_id", "sig", "step_number", "timestamp_utc"}

// ParseEvent strictly decodes an event JSON document (as written in evidence
// bundles and exported event.json files). The document must have exactly the
// nine canonical fields; member order and whitespace are free, but hex values
// must be 0x-prefixed lowercase so that the canonical form is unique.
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
	if len(fields) != len(eventFields) {
		return Event{}, fmt.Errorf("%w: event must have exactly the fields %s", ErrInvalidEvent, strings.Join(eventFields, ", "))
	}
	for _, k := range eventFields {
		if _, ok := fields[k]; !ok {
			return Event{}, fmt.Errorf("%w: missing field %q", ErrInvalidEvent, k)
		}
	}
	str := func(k string) (string, error) {
		s, ok := fields[k].(string)
		if !ok {
			return "", fmt.Errorf("%w: %s must be a string", ErrInvalidEvent, k)
		}
		return s, nil
	}

	var ev Event
	if ev.AgentID, err = str("agent_id"); err != nil {
		return Event{}, err
	}
	if ev.EventType, err = str("event_type"); err != nil {
		return Event{}, err
	}
	if ev.RunID, err = str("run_id"); err != nil {
		return Event{}, err
	}
	num, ok := fields["step_number"].(json.Number)
	if !ok {
		return Event{}, fmt.Errorf("%w: step_number must be a number", ErrInvalidEvent)
	}
	if ev.StepNumber, err = strconv.ParseUint(string(num), 10, 64); err != nil {
		return Event{}, fmt.Errorf("%w: step_number must be a non-negative 64-bit integer", ErrInvalidEvent)
	}
	ts, err := str("timestamp_utc")
	if err != nil {
		return Event{}, err
	}
	if ev.TimestampUTC, err = time.Parse(TimestampLayout, ts); err != nil {
		return Event{}, fmt.Errorf("%w: timestamp_utc must have the form %s", ErrInvalidEvent, TimestampLayout)
	}
	for _, h := range []struct {
		name string
		dst  []byte
	}{{"key_id", ev.KeyID[:]}, {"prev_hash", ev.PrevHash[:]}} {
		s, err := str(h.name)
		if err != nil {
			return Event{}, err
		}
		b, err := parseLowerHex(s, len(h.dst))
		if err != nil {
			return Event{}, fmt.Errorf("%w: %s: %v", ErrInvalidEvent, h.name, err)
		}
		copy(h.dst, b)
	}
	sig, err := str("sig")
	if err != nil {
		return Event{}, err
	}
	if ev.Sig, err = parseLowerHex(sig, ed25519.SignatureSize); err != nil {
		return Event{}, fmt.Errorf("%w: sig: %v", ErrInvalidEvent, err)
	}
	var pbuf bytes.Buffer
	if err := encode(&pbuf, fields["payload"]); err != nil {
		return Event{}, err
	}
	ev.PayloadJSON = pbuf.Bytes()
	return ev, ev.Validate()
}

// parseLowerHex decodes "0x" followed by exactly 2*n lowercase hex digits.
func parseLowerHex(s string, n int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") || len(s) != 2+2*n {
		return nil, fmt.Errorf("must be 0x followed by %d hex characters", 2*n)
	}
	for _, c := range s[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, errors.New("must be lowercase hex")
		}
	}
	return hex.DecodeString(s[2:])
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
