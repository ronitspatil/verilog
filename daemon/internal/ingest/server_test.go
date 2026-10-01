package ingest

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
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
}

func newEnv(t *testing.T) *env {
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
	srv := grpc.NewServer()
	verilogv1.RegisterVeriLogServer(srv, NewServer(eng, st, Options{MaxPayloadBytes: 4096, Window: 64}, nil))
	go srv.Serve(lis)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
		srv.Stop()
		cancel()
		eng.Close()
		w.Close()
	})
	return &env{client: verilogv1.NewVeriLogClient(conn), eng: eng, sink: sink}
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
