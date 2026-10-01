package canonical

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalizeJSON(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{" { \"a\" : [ 1 , 2 , { \"z\" : null , \"y\" : true } ] } ", `{"a":[1,2,{"y":true,"z":null}]}`},
		{`"<script>&</script>"`, `"<script>&</script>"`}, // no HTML escaping
		{`"\u00e9\u20ac\ud83d\ude00"`, `"é€😀"`},          // escapes decoded to UTF-8
		{`"\u2028\u2029"`, "\"\u2028\u2029\""},           // not escaped by JCS
		{`"\u0000\u001f\b\f\n\r\t\"\\\/"`, `"\u0000\u001f\b\f\n\r\t\"\\/"`},
		{`123456789012345678901234567890`, `123456789012345678901234567890`}, // exact integer
		{`-0`, `0`},
		{`18446744073709551615`, `18446744073709551615`},
		{`1.0`, `1`},
		{`1e2`, `100`},
		{`0.1`, `0.1`},
		{`-1.5e-7`, `-1.5e-7`},
		{`1e21`, `1e+21`},
		{`1e20`, `100000000000000000000`},
		{`123456789.123456789`, `123456789.12345679`},
		{`[]`, `[]`},
		{`{}`, `{}`},
		// RFC 8785 section 3.2.3 sorting example (UTF-16 code unit order).
		{`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
	}
	for _, c := range cases {
		got, err := CanonicalizeJSON([]byte(c.in))
		if err != nil {
			t.Errorf("CanonicalizeJSON(%s): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("CanonicalizeJSON(%s)\n got  %s\n want %s", c.in, got, c.want)
		}
		// Idempotence.
		again, err := CanonicalizeJSON(got)
		if err != nil || string(again) != string(got) {
			t.Errorf("not idempotent for %s: %s (%v)", c.in, again, err)
		}
	}
}

func TestCanonicalizeJSONRejects(t *testing.T) {
	for _, in := range []string{
		``, `{`, `{"a":1,"a":2}`, `{"a":1} x`, `[1,]`, `01`, `NaN`, `1e400`,
		"\"\xff\"",
	} {
		if _, err := CanonicalizeJSON([]byte(in)); !errors.Is(err, ErrInvalidJSON) {
			t.Errorf("CanonicalizeJSON(%q) err = %v, want ErrInvalidJSON", in, err)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	deep := make([]byte, 0, 2*(maxDepth+2))
	for i := 0; i < maxDepth+2; i++ {
		deep = append(deep, '[')
	}
	for i := 0; i < maxDepth+2; i++ {
		deep = append(deep, ']')
	}
	if _, err := CanonicalizeJSON(deep); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("expected depth error, got %v", err)
	}
}

func TestFormatES6Float(t *testing.T) {
	// Values from RFC 8785 Appendix B (IEEE-754 bit patterns and expected output).
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, c := range cases {
		got, err := FormatES6Float(math.Float64frombits(c.bits))
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("FormatES6Float(%#x) = %s, want %s", c.bits, got, c.want)
		}
	}
	if _, err := FormatES6Float(math.NaN()); err == nil {
		t.Error("NaN must be rejected")
	}
	if _, err := FormatES6Float(math.Inf(1)); err == nil {
		t.Error("Inf must be rejected")
	}
}

var testPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func sampleEvent() Event {
	ev := Event{
		AgentID:      "agent-alpha",
		RunID:        "run-1",
		StepNumber:   7,
		PrevHash:     ContentDigest([]byte("previous")),
		EventType:    "tool_start",
		PayloadJSON:  []byte(`{"tool": "search", "input": {"q": "weather", "k": 3}}`),
		TimestampUTC: time.Date(2026, 9, 30, 12, 0, 0, 123456789, time.UTC),
	}
	if err := ev.Sign(testPriv); err != nil {
		panic(err)
	}
	return ev
}

func TestEventCanonical(t *testing.T) {
	ev := sampleEvent()
	got, err := ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_id":"agent-alpha","event_type":"tool_start","key_id":"` + ev.KeyID.Hex() +
		`","payload":{"input":{"k":3,"q":"weather"},"tool":"search"},"prev_hash":"` + ev.PrevHash.Hex() +
		`","run_id":"run-1","sig":"0x` + hex.EncodeToString(ev.Sig) +
		`","step_number":7,"timestamp_utc":"2026-09-30T12:00:00.123456789Z"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	msg, err := ev.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	wantMsg := SigningDomain + strings.Replace(want, `"sig":"0x`+hex.EncodeToString(ev.Sig)+`",`, "", 1)
	if string(msg) != wantMsg {
		t.Fatalf("signing bytes\n got  %s\n want %s", msg, wantMsg)
	}
}

func TestEventTimestampNormalizedToUTC(t *testing.T) {
	ev := sampleEvent()
	ev.TimestampUTC = ev.TimestampUTC.In(time.FixedZone("X", 5*3600))
	a, _ := ev.Canonical()
	b, _ := sampleEvent().Canonical()
	if string(a) != string(b) {
		t.Fatal("same instant in different zones must canonicalize identically")
	}
}

func TestParseEventRoundTrip(t *testing.T) {
	ev0 := sampleEvent()
	canon, _ := ev0.Canonical()
	// Reformatted (whitespace, member order) input parses to the same event.
	reformatted := `{
	  "timestamp_utc": "2026-09-30T12:00:00.123456789Z", "sig": "0x` + hex.EncodeToString(ev0.Sig) + `",
	  "payload": {"tool": "search", "input": {"k": 3, "q": "weather"}}, "run_id": "run-1",
	  "prev_hash": "` + ev0.PrevHash.Hex() + `", "key_id": "` + ev0.KeyID.Hex() + `",
	  "step_number": 7, "event_type": "tool_start", "agent_id": "agent-alpha"
	}`
	for _, doc := range []string{string(canon), reformatted} {
		ev, err := ParseEvent([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		again, err := ev.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(canon) {
			t.Fatalf("round trip mismatch:\n%s\n%s", again, canon)
		}
		if err := ev.VerifySig(testPriv.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseEventRejects(t *testing.T) {
	canon, _ := sampleEvent().Canonical()
	good := string(canon)
	ev := sampleEvent()
	sigHex := "0x" + hex.EncodeToString(ev.Sig)
	replace := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("test bug: %q not in %s", old, good)
		}
		return strings.Replace(good, old, new, 1)
	}
	for _, doc := range []string{
		`[]`,
		replace(`"step_number":7,`, ``), // missing field
		replace(`"step_number":7`, `"step_number":7,"extra":1`),  // extra field
		replace(`"step_number":7`, `"step_number":-1`),           // negative
		replace(`"step_number":7`, `"step_number":1.5`),          // fraction
		replace(`.123456789Z`, `Z`),                              // timestamp precision
		replace(`"agent_id":"agent-alpha"`, `"agent_id":""`),     // empty agent
		replace(`"agent_id":"agent-alpha"`, `"agent_id":1`),      // wrong type
		replace(`"run_id":"run-1"`, `"run_id":""`),               // empty run
		replace(ev.KeyID.Hex(), strings.ToUpper(ev.KeyID.Hex())), // uppercase hex
		replace(ev.PrevHash.Hex(), ev.PrevHash.Hex()[2:]),        // no 0x
		replace(ev.KeyID.Hex(), Digest{}.Hex()),                  // zero key id
		replace(sigHex, sigHex[:len(sigHex)-2]),                  // short sig
		replace(`"sig":"`+sigHex+`",`, ``),                       // unsigned
	} {
		if _, err := ParseEvent([]byte(doc)); err == nil {
			t.Errorf("ParseEvent accepted %s", doc)
		}
	}
}

func TestEventValidate(t *testing.T) {
	ev := sampleEvent()
	ev.PayloadJSON = []byte(`{bad`)
	if _, err := ev.Canonical(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("err = %v", err)
	}
	ev = sampleEvent()
	ev.TimestampUTC = time.Time{}
	if _, err := ev.Canonical(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("err = %v", err)
	}
	ev = sampleEvent()
	ev.Sig = nil
	if _, err := ev.Canonical(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("unsigned event: err = %v", err)
	}
	if _, err := ev.SigningBytes(); err != nil {
		t.Fatalf("SigningBytes must not need a signature: %v", err)
	}
}

// TestMutationsBreakDigestOrSignature changes every field (and the signature)
// in turn: each change must alter the content digest, and every change except
// re-signing must also fail signature verification.
func TestMutationsBreakDigestOrSignature(t *testing.T) {
	pub := testPriv.Public().(ed25519.PublicKey)
	base := sampleEvent()
	baseCanon, _ := base.Canonical()
	baseDigest := ContentDigest(baseCanon)
	mutations := map[string]func(*Event){
		"agent_id":      func(e *Event) { e.AgentID += "x" },
		"run_id":        func(e *Event) { e.RunID = "run-2" },
		"step_number":   func(e *Event) { e.StepNumber++ },
		"prev_hash":     func(e *Event) { e.PrevHash[0] ^= 1 },
		"event_type":    func(e *Event) { e.EventType = "tool_end" },
		"payload":       func(e *Event) { e.PayloadJSON = []byte(`{"tool":"search","input":{"q":"weather","k":4}}`) },
		"timestamp_utc": func(e *Event) { e.TimestampUTC = e.TimestampUTC.Add(time.Nanosecond) },
		"key_id":        func(e *Event) { e.KeyID[31] ^= 1 },
		"sig":           func(e *Event) { e.Sig = append([]byte(nil), e.Sig...); e.Sig[0] ^= 1 },
	}
	for name, mutate := range mutations {
		ev := sampleEvent()
		mutate(&ev)
		canon, err := ev.Canonical()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ContentDigest(canon) == baseDigest {
			t.Errorf("%s: mutation did not change the content digest", name)
		}
		if err := ev.VerifySig(pub); err == nil {
			t.Errorf("%s: mutated event still verifies", name)
		}
	}
	// A different key's valid signature fails against the original key.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	ev := sampleEvent()
	if err := ev.Sign(other); err != nil {
		t.Fatal(err)
	}
	if err := ev.VerifySig(pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("foreign key: err = %v", err)
	}
	if err := ev.VerifySig(other.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("own key: %v", err)
	}
}

// TestSignedVectors reproduces testdata/signed_vectors.json and
// testdata/canonical_vectors.json (generated by internal/vectors) from their
// inputs and the published test seed.
func TestSignedVectors(t *testing.T) {
	for _, file := range []string{"signed_vectors.json", "canonical_vectors.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		var vf struct {
			Run   []vectorCase `json:"run"`
			Cases []vectorCase `json:"cases"`
			Seed  string       `json:"seed"`
		}
		if err := json.Unmarshal(data, &vf); err != nil {
			t.Fatal(err)
		}
		seed, err := hex.DecodeString(strings.TrimPrefix(vf.Seed, "0x"))
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("%s: bad seed %q", file, vf.Seed)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		cases := append(vf.Run, vf.Cases...)
		if len(cases) == 0 {
			t.Fatalf("%s: no cases", file)
		}
		var prev Digest
		for i, c := range cases {
			ts, err := time.Parse(TimestampLayout, c.TimestampUTC)
			if err != nil {
				t.Fatal(err)
			}
			ev := Event{AgentID: c.AgentID, RunID: c.RunID, StepNumber: c.StepNumber, EventType: c.EventType,
				PayloadJSON: []byte(c.PayloadJSON), TimestampUTC: ts, PrevHash: prev}
			if ev.PrevHash.Hex() != c.PrevHash || ev.StepNumber != uint64(i+1) {
				t.Fatalf("%s/%s: chain link mismatch", file, c.Name)
			}
			if err := ev.Sign(priv); err != nil {
				t.Fatal(err)
			}
			msg, _ := ev.SigningBytes()
			canon, err := ev.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			d := ContentDigest(canon)
			switch {
			case ev.KeyID.Hex() != c.KeyID:
				t.Errorf("%s/%s: key_id %s, want %s", file, c.Name, ev.KeyID.Hex(), c.KeyID)
			case string(msg) != c.SigningBytes:
				t.Errorf("%s/%s: signing bytes differ", file, c.Name)
			case "0x"+hex.EncodeToString(ev.Sig) != c.Sig:
				t.Errorf("%s/%s: signature differs", file, c.Name)
			case string(canon) != c.CanonicalEvent:
				t.Errorf("%s/%s: canonical event differs", file, c.Name)
			case d.Hex() != c.ContentDigest:
				t.Errorf("%s/%s: digest differs", file, c.Name)
			}
			prev = d
		}
	}
}

type vectorCase struct {
	Name           string `json:"name"`
	AgentID        string `json:"agent_id"`
	RunID          string `json:"run_id"`
	StepNumber     uint64 `json:"step_number"`
	PrevHash       string `json:"prev_hash"`
	EventType      string `json:"event_type"`
	PayloadJSON    string `json:"payload_json"`
	TimestampUTC   string `json:"timestamp_utc"`
	KeyID          string `json:"key_id"`
	SigningBytes   string `json:"signing_bytes"`
	Sig            string `json:"sig"`
	CanonicalEvent string `json:"canonical_event"`
	ContentDigest  string `json:"content_digest"`
}

func TestAgentKey(t *testing.T) {
	// Computed independently with `cast keccak agent-alpha`.
	const want = "0x765069f0d82dd70961ef67543724ecc2bc8bbdc4d1183662c723dc57f80e3720"
	if got := AgentKey("agent-alpha").Hex(); got != want {
		t.Fatalf("AgentKey = %s, want %s", got, want)
	}
}

func TestParseDigest(t *testing.T) {
	d := ContentDigest([]byte("x"))
	back, err := ParseDigest(d.Hex())
	if err != nil || back != d {
		t.Fatalf("ParseDigest round trip failed: %v", err)
	}
	if _, err := ParseDigest("0x1234"); err == nil {
		t.Fatal("short digest accepted")
	}
}
