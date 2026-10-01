package ingest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
	"github.com/ronitspatil/verilog/daemon/internal/keys"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/wal"
)

type jobSink struct {
	mu   sync.Mutex
	jobs []anchor.Job
}

func (s *jobSink) Enqueue(j anchor.Job) { s.mu.Lock(); s.jobs = append(s.jobs, j); s.mu.Unlock() }

type env struct {
	client verilogv1.VeriLogClient
	eng    *engine.Engine
	sink   *jobSink
	keys   *fakeKeys
	// dial opens another client connection with the given credentials.
	dial func(t *testing.T, creds credentials.TransportCredentials) verilogv1.VeriLogClient
}

// envOptions configures newEnvWith.
type envOptions struct {
	server []grpc.ServerOption              // e.g. grpc.Creds for mTLS
	client credentials.TransportCredentials // creds of env.client (insecure if nil)
	opts   Options                          // Authz and IdleTimeout are used
}

// fakeKeys is an in-memory key registry: keyID -> key, for every agent.
type fakeKeys struct {
	mu    sync.Mutex
	keys  map[canonical.Digest]keys.Key
	err   error
	calls int
}

func (f *fakeKeys) AgentKey(_ context.Context, _, keyID canonical.Digest) (keys.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return keys.Key{}, f.err
	}
	return f.keys[keyID], nil
}

func (f *fakeKeys) set(priv ed25519.PrivateKey, k keys.Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pub := priv.Public().(ed25519.PublicKey)
	k.Pubkey = pub
	f.keys[canonical.KeyID(pub)] = k
}

func newEnv(t *testing.T) *env { return newEnvWith(t, envOptions{}) }

func newEnvWith(t *testing.T, o envOptions) *env {
	t.Helper()
	dir := t.TempDir()
	w, recs, err := wal.Open(dir+"/wal", 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(dir)
	sink := &jobSink{}
	eng, err := engine.New(engine.Config{EpochInterval: time.Hour, EpochMaxLogs: 1 << 20}, w, st, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	eng.Recover(recs)
	ctx, cancel := context.WithCancel(context.Background())
	eng.Start(ctx)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(o.server...)
	reg := &fakeKeys{keys: map[canonical.Digest]keys.Key{}}
	reg.set(testKey, keys.Key{ValidFrom: 1})
	verilogv1.RegisterVeriLogServer(srv, NewServer(eng, st, Options{MaxPayloadBytes: 4096, Window: 64, Keys: reg,
		Authz: o.opts.Authz, IdleTimeout: o.opts.IdleTimeout}, nil))
	go srv.Serve(lis)
	t.Cleanup(func() {
		srv.Stop()
		cancel()
		eng.Close()
		w.Close()
	})
	dial := func(t *testing.T, creds credentials.TransportCredentials) verilogv1.VeriLogClient {
		t.Helper()
		if creds == nil {
			creds = insecure.NewCredentials()
		}
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return verilogv1.NewVeriLogClient(conn)
	}
	return &env{client: dial(t, o.client), eng: eng, sink: sink, keys: reg, dial: dial}
}

var testKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// logEvent returns a LogEvent signed with priv (testKey when nil).
func logEventWith(priv ed25519.PrivateKey, agent string, seq uint64) *verilogv1.LogEvent {
	if priv == nil {
		priv = testKey
	}
	ev := canonical.Event{
		AgentID:      agent,
		RunID:        "run-" + agent,
		StepNumber:   seq,
		EventType:    "tool_end",
		PayloadJSON:  []byte(fmt.Sprintf(`{"output": "result %d", "ok": true}`, seq)),
		TimestampUTC: time.Unix(1_800_000_000, int64(seq)).UTC(),
	}
	if err := ev.Sign(priv); err != nil {
		panic(err)
	}
	return &verilogv1.LogEvent{
		AgentId:      ev.AgentID,
		RunId:        ev.RunID,
		StepNumber:   ev.StepNumber,
		PrevHash:     ev.PrevHash[:],
		EventType:    ev.EventType,
		PayloadJson:  string(ev.PayloadJSON),
		TimestampUtc: timestamppb.New(ev.TimestampUTC),
		KeyId:        ev.KeyID[:],
		Signature:    ev.Sig,
		Sequence:     seq,
	}
}

func logEvent(agent string, seq uint64) *verilogv1.LogEvent { return logEventWith(nil, agent, seq) }

func expectedDigest(t *testing.T, m *verilogv1.LogEvent) canonical.Digest {
	ev, err := eventFromProto(m)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical.ContentDigest(canon)
}

func TestStreamAcksInOrder(t *testing.T) {
	e := newEnv(t)
	stream, err := e.client.IngestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const n = 500
	msgs := make([]*verilogv1.LogEvent, n)
	go func() {
		for i := range msgs {
			msgs[i] = logEvent("agent-a", uint64(i+1))
		}
		for _, m := range msgs {
			if err := stream.Send(m); err != nil {
				t.Error(err)
				return
			}
		}
		stream.CloseSend()
	}()
	for i := 0; i < n; i++ {
		ack, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if ack.Sequence != uint64(i+1) || !ack.Accepted || ack.Duplicate {
			t.Fatalf("ack %d: %+v", i, ack)
		}
		want := expectedDigest(t, msgs[i])
		if string(ack.ContentDigest) != string(want[:]) {
			t.Fatalf("ack %d digest mismatch", i)
		}
		if leaf := merkle.LeafFromDigest(want); string(ack.Leaf) != string(leaf[:]) {
			t.Fatalf("ack %d leaf mismatch", i)
		}
	}
	if s := e.eng.Stats(); s.Accepted != n {
		t.Fatalf("accepted = %d", s.Accepted)
	}
}

func TestStreamRejectsInvalidEventsButContinues(t *testing.T) {
	e := newEnv(t)
	stream, _ := e.client.IngestStream(context.Background())
	bad := []*verilogv1.LogEvent{
		{AgentId: "a", EventType: "x", PayloadJson: `{not json`, TimestampUtc: timestamppb.Now(), Sequence: 1},
		{AgentId: "", EventType: "x", PayloadJson: `{}`, TimestampUtc: timestamppb.Now(), Sequence: 2},
		{AgentId: "a", EventType: "x", PayloadJson: `{}`, Sequence: 3},
		{AgentId: "a", EventType: "x", PayloadJson: fmt.Sprintf(`{"big":"%0*d"}`, 5000, 0), TimestampUtc: timestamppb.Now(), Sequence: 4},
	}
	good := logEvent("a", 5)
	for _, m := range append(bad, good) {
		stream.Send(m)
	}
	stream.CloseSend()
	for i := 0; i < len(bad); i++ {
		ack, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if ack.Accepted || ack.Error == "" || ack.Sequence != uint64(i+1) {
			t.Fatalf("bad event %d acked as %+v", i+1, ack)
		}
	}
	ack, err := stream.Recv()
	if err != nil || !ack.Accepted || ack.Sequence != 5 {
		t.Fatalf("good event after bad ones: %+v %v", ack, err)
	}
}

func TestConcurrentStreams(t *testing.T) {
	e := newEnv(t)
	const streams, perStream = 8, 200
	var wg sync.WaitGroup
	for s := 0; s < streams; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			stream, err := e.client.IngestStream(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			agent := fmt.Sprintf("agent-%d", s%3)
			go func() {
				for i := 0; i < perStream; i++ {
					stream.Send(logEvent(agent, uint64(s*10_000+i+1)))
				}
				stream.CloseSend()
			}()
			for i := 0; i < perStream; i++ {
				ack, err := stream.Recv()
				if err != nil || !ack.Accepted {
					t.Errorf("stream %d ack %d: %+v %v", s, i, ack, err)
					return
				}
			}
		}(s)
	}
	wg.Wait()
	if got := e.eng.Stats().Accepted; got != streams*perStream {
		t.Fatalf("accepted = %d, want %d", got, streams*perStream)
	}
}

func TestGetProof(t *testing.T) {
	e := newEnv(t)
	stream, _ := e.client.IngestStream(context.Background())
	var msgs []*verilogv1.LogEvent
	for i := uint64(1); i <= 5; i++ {
		m := logEvent("agent-p", i)
		msgs = append(msgs, m)
		stream.Send(m)
	}
	stream.CloseSend()
	for range msgs {
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()

	_, err := e.client.GetProof(ctx, &verilogv1.GetProofRequest{AgentId: "agent-p", EpochId: 1, Selector: &verilogv1.GetProofRequest_LeafIndex{LeafIndex: 0}})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("before anchoring: %v, want NotFound", err)
	}

	e.eng.SealAll(ctx)
	e.sink.mu.Lock()
	job := e.sink.jobs[0]
	e.sink.mu.Unlock()
	if err := job.Done(ctx, anchor.Result{EpochID: 1, TxHash: "0xfeed", BlockNumber: 9}); err != nil {
		t.Fatal(err)
	}

	want := expectedDigest(t, msgs[3])
	for _, req := range []*verilogv1.GetProofRequest{
		{AgentId: "agent-p", EpochId: 1, Selector: &verilogv1.GetProofRequest_LeafIndex{LeafIndex: 3}},
		{AgentId: "agent-p", EpochId: 1, Selector: &verilogv1.GetProofRequest_ContentDigest{ContentDigest: want[:]}},
	} {
		resp, err := e.client.GetProof(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if string(resp.ContentDigest) != string(want[:]) || resp.LeafIndex != 3 || resp.TxHash != "0xfeed" {
			t.Fatalf("resp %+v", resp)
		}
		var root, leaf merkle.Hash
		copy(root[:], resp.MerkleRoot)
		copy(leaf[:], resp.Leaf)
		var proof []merkle.Hash
		for _, p := range resp.Proof {
			var h merkle.Hash
			copy(h[:], p)
			proof = append(proof, h)
		}
		if !merkle.Verify(leaf, proof, root) || job.Root != root {
			t.Fatal("GetProof returned an invalid proof")
		}
	}
	_, err = e.client.GetProof(ctx, &verilogv1.GetProofRequest{AgentId: "agent-p", EpochId: 1, Selector: &verilogv1.GetProofRequest_LeafIndex{LeafIndex: 99}})
	if status.Code(err) != codes.OutOfRange {
		t.Fatalf("out of range: %v", err)
	}
	_, err = e.client.GetProof(ctx, &verilogv1.GetProofRequest{AgentId: "agent-p"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing epoch: %v", err)
	}
}

func TestStreamEnforcesSignatures(t *testing.T) {
	e := newEnv(t)
	unregistered := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	revoked := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	e.keys.set(revoked, keys.Key{ValidFrom: 1, RevokedAt: 2})
	// A revocation recorded for the future already stops intake (drain window).
	scheduled := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	e.keys.set(scheduled, keys.Key{ValidFrom: 1, RevokedAt: 1 << 40})

	good := logEvent("agent-s", 1)
	unsigned := logEvent("agent-s", 2)
	unsigned.Signature = nil
	// Claims the registered key but is signed by another one (a forgery).
	wrongKey := logEventWith(unregistered, "agent-s", 3)
	wrongKey.KeyId = good.KeyId
	unknownKey := logEventWith(unregistered, "agent-s", 4)
	revokedKey := logEventWith(revoked, "agent-s", 5)
	// A valid signature over different content (payload altered after signing).
	altered := logEvent("agent-s", 6)
	altered.PayloadJson = `{"output": "something else", "ok": true}`
	shortKeyID := logEvent("agent-s", 7)
	shortKeyID.KeyId = shortKeyID.KeyId[:31]
	good2 := logEvent("agent-s", 8)
	scheduledKey := logEventWith(scheduled, "agent-s", 9)
	// A small-order key registered in an older registry (H1): rejected.
	weak := logEventWith(nil, "agent-s", 10)
	var identity [32]byte
	identity[0] = 1
	weakID := canonical.KeyID(identity[:])
	weak.KeyId = weakID[:]
	e.keys.mu.Lock()
	e.keys.keys[weakID] = keys.Key{Pubkey: identity[:], ValidFrom: 1}
	e.keys.mu.Unlock()

	cases := []struct {
		msg       *verilogv1.LogEvent
		accepted  bool
		errHas    string
		retryable bool
	}{
		{good, true, "", false},
		{unsigned, false, "not signed", false},
		{wrongKey, false, "signature does not verify", false},
		{unknownKey, false, "not registered", true}, // may just not be visible yet
		{revokedKey, false, "revoked", false},
		{altered, false, "signature does not verify", false},
		{shortKeyID, false, "key_id must be 32 bytes", false},
		{good2, true, "", false},
		{scheduledKey, false, "revoked (effective at", false},
		{weak, false, "small order", false},
	}
	stream, err := e.client.IngestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if err := stream.Send(c.msg); err != nil {
			t.Fatal(err)
		}
	}
	stream.CloseSend()
	for _, c := range cases {
		ack, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if ack.Sequence != c.msg.Sequence || ack.Accepted != c.accepted || !strings.Contains(ack.Error, c.errHas) || ack.Retryable != c.retryable {
			t.Errorf("event %d: ack %+v, want accepted=%v error containing %q", c.msg.Sequence, ack, c.accepted, c.errHas)
		}
	}
	if got := e.eng.Stats().Accepted; got != 2 {
		t.Fatalf("accepted = %d, want 2", got)
	}
}

func TestStreamFailsWhenKeyRegistryIsDown(t *testing.T) {
	e := newEnv(t)
	stream, err := e.client.IngestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(logEvent("agent-d", 1)); err != nil {
		t.Fatal(err)
	}
	if ack, err := stream.Recv(); err != nil || !ack.Accepted {
		t.Fatalf("first event: %+v %v", ack, err)
	}
	// Registry outage: the event is neither accepted nor rejected; the stream
	// fails with UNAVAILABLE so the client re-sends it after reconnecting.
	e.keys.mu.Lock()
	e.keys.err = errors.New("rpc down")
	e.keys.mu.Unlock()
	stream.Send(logEventWith(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), "agent-d", 2))
	_, err = stream.Recv()
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

// PoC 6 (H2, daemon side): with verilogd's receive limit, a payload over the
// cap is a per-event rejection, and the stream goes on, even when the
// message is far larger than the cap.
func TestOversizedPayloadIsRejectedPerEvent(t *testing.T) {
	const P = 1 << 16
	dir := t.TempDir()
	w, recs, _ := wal.Open(dir+"/wal", 1<<26, nil)
	st, _ := store.Open(dir)
	eng, _ := engine.New(engine.Config{EpochInterval: time.Hour, EpochMaxLogs: 1 << 20}, w, st, &jobSink{}, nil)
	eng.Recover(recs)
	ctx, cancel := context.WithCancel(context.Background())
	eng.Start(ctx)
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(MaxRecvMsgSize(P)))
	reg := &fakeKeys{keys: map[canonical.Digest]keys.Key{}}
	reg.set(testKey, keys.Key{ValidFrom: 1})
	verilogv1.RegisterVeriLogServer(srv, NewServer(eng, st, Options{MaxPayloadBytes: P, Window: 64, Keys: reg}, nil))
	go srv.Serve(lis)
	conn, _ := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { conn.Close(); srv.Stop(); cancel(); eng.Close(); w.Close() })

	big := func(n int, seq uint64) *verilogv1.LogEvent {
		ev := canonical.Event{AgentID: "a", RunID: "r", StepNumber: seq, EventType: "tool_end",
			PayloadJSON: []byte(`{"output":"` + strings.Repeat("x", n) + `"}`), TimestampUTC: time.Unix(1_800_000_000, 0).UTC()}
		if err := ev.Sign(testKey); err != nil {
			t.Fatal(err)
		}
		return &verilogv1.LogEvent{AgentId: ev.AgentID, RunId: ev.RunID, StepNumber: seq, EventType: ev.EventType,
			PayloadJson: string(ev.PayloadJSON), TimestampUtc: timestamppb.New(ev.TimestampUTC),
			PrevHash: ev.PrevHash[:], KeyId: ev.KeyID[:], Signature: ev.Sig, Sequence: seq}
	}
	stream, err := verilogv1.NewVeriLogClient(conn).IngestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range []int{P + 10, 2 * P, 3 * P, 10} {
		if err := stream.Send(big(n, uint64(i+1))); err != nil {
			t.Fatal(err)
		}
		ack, err := stream.Recv()
		if err != nil {
			t.Fatalf("%d-byte payload killed the stream: %v", n, err)
		}
		if want := n <= P; ack.Accepted != want {
			t.Fatalf("%d-byte payload: %+v", n, ack)
		}
		if !ack.Accepted && (ack.Retryable || !strings.Contains(ack.Error, "size limit")) {
			t.Fatalf("%d-byte payload: %+v", n, ack)
		}
	}
}
