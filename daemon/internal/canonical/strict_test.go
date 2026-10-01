package canonical

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// M1 / PoC 1: an event file that parses to the same event but is spelled
// differently (here a number the agent signed as 9007199254740992 shown as
// 9007199254740993.0) must be refused, not silently re-canonicalized.
func TestParseCanonicalEventIsStrict(t *testing.T) {
	ev := Event{AgentID: "a", RunID: "r", StepNumber: 1, EventType: "tool_end",
		PayloadJSON: []byte(`{"amount":9007199254740992,"to":"acct-1"}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC()}
	if err := ev.Sign(ed25519.NewKeyFromSeed(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	canon, _ := ev.Canonical()
	if _, got, err := ParseCanonicalEvent(append(append([]byte(nil), canon...), '\n')); err != nil || !bytes.Equal(got, canon) {
		t.Fatalf("canonical file with newline: %v", err)
	}
	for name, doc := range map[string][]byte{
		"float spelling": bytes.Replace(canon, []byte(`9007199254740992`), []byte(`9007199254740993.0`), 1),
		"escape":         bytes.Replace(canon, []byte(`"acct-1"`), []byte(`"\u0061cct-1"`), 1),
		"whitespace":     bytes.Replace(canon, []byte(`,`), []byte(`, `), 1),
		"two newlines":   append(append([]byte(nil), canon...), '\n', '\n'),
		"crlf":           append(append([]byte(nil), canon...), '\r', '\n'),
	} {
		parsed, got, err := ParseCanonicalEvent(doc)
		if !errors.Is(err, ErrNotCanonical) || !bytes.Equal(got, canon) {
			t.Errorf("%s: err=%v", name, err)
		}
		if name == "float spelling" && parsed.VerifySig(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)) != nil {
			t.Errorf("precondition: the altered file still carries a valid signature")
		}
	}
}
