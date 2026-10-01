package canonical

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

// The encodings VeriLogRegistry.isWeakPubkey refuses on chain. Every one must
// also be refused here.
var contractWeakKeys = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestCheckPublicKeyRejectsWeakKeys(t *testing.T) {
	for _, h := range contractWeakKeys {
		b, _ := hex.DecodeString(h)
		if err := CheckPublicKey(b); !errors.Is(err, ErrWeakPublicKey) {
			t.Errorf("%s accepted", h)
		}
	}
	// The first eight are exactly the canonical small-order points: [8]P = identity.
	for _, h := range contractWeakKeys[:8] {
		b, _ := hex.DecodeString(h)
		p, err := new(edwards25519.Point).SetBytes(b)
		if err != nil || !bytes.Equal(p.Bytes(), b) || new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) != 1 {
			t.Errorf("%s is not a canonical small-order point", h)
		}
	}
	// Mixed order: a valid key plus a torsion point. Its [8]P is not the
	// identity, so only the prime-order-subgroup check catches it.
	good := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey)
	a, _ := new(edwards25519.Point).SetBytes(good)
	tor, _ := hex.DecodeString(contractWeakKeys[4])
	tp, _ := new(edwards25519.Point).SetBytes(tor)
	mixed := new(edwards25519.Point).Add(a, tp).Bytes()
	if err := CheckPublicKey(mixed); err == nil || !strings.Contains(err.Error(), "mixed order") {
		t.Fatalf("mixed-order key: %v", err)
	}
	if err := CheckPublicKey(good); err != nil {
		t.Fatal(err)
	}
	if err := CheckPublicKey(good[:31]); err == nil {
		t.Fatal("short key accepted")
	}
	// Not on the curve.
	off, _ := hex.DecodeString("0200000000000000000000000000000000000000000000000000000000000000")
	if err := CheckPublicKey(off); err == nil {
		t.Fatal("off-curve key accepted")
	}
}

// H1 / PoC 4: with the identity point as public key, R = identity and S = 0
// verify for any message under crypto/ed25519. VerifySig must refuse it.
func TestVerifySigRejectsSmallOrderKey(t *testing.T) {
	weak := make(ed25519.PublicKey, 32)
	weak[0] = 1
	sig := make([]byte, 64)
	sig[0] = 1
	ev := Event{AgentID: "a", RunID: "r", StepNumber: 1, EventType: "tool_end", PayloadJSON: []byte(`{"action":"wire $1M"}`),
		TimestampUTC: time.Unix(1_800_000_000, 0).UTC(), KeyID: KeyID(weak), Sig: sig}
	msg, _ := ev.SigningBytes()
	if !ed25519.Verify(weak, msg, sig) {
		t.Fatal("precondition: stdlib accepts the forgery")
	}
	if err := ev.VerifySig(weak); !errors.Is(err, ErrBadSignature) || !strings.Contains(err.Error(), "small order") {
		t.Fatalf("forged signature accepted: %v", err)
	}
}

func TestProofOfPossession(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	agent := AgentKey("agent-pop")
	pop := SignPoP(priv, agent)
	if err := CheckKeyRegistration(agent, pub, pop); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(PoPMessage(agent, pub), []byte("VeriLog/pop/v1\n")) || len(PoPMessage(agent, pub)) != 15+64 {
		t.Fatal("PoP message layout")
	}
	if CheckKeyRegistration(AgentKey("other-agent"), pub, pop) == nil {
		t.Fatal("PoP for another agent accepted")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	if CheckKeyRegistration(agent, other.Public().(ed25519.PublicKey), pop) == nil {
		t.Fatal("PoP of another key accepted")
	}
	weak := make([]byte, 32)
	weak[0] = 1
	if CheckKeyRegistration(agent, weak, make([]byte, 64)) == nil {
		t.Fatal("weak key accepted")
	}
}
