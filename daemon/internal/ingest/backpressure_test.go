package ingest

import (
	"context"
	"strings"
	"testing"

	"github.com/ronitspatil/verilog/daemon/internal/anchor"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
)

// M6: an agent over its quota gets retryable rejections with a retry delay
// and nothing is written; another agent's events are still accepted, and the
// refused event is accepted when re-sent once the quota frees up.
func TestQuotaRejectionIsRetryableWithDelay(t *testing.T) {
	e := newEnvWith(t, envOptions{limits: engine.Limits{MaxAgentEvents: 2}})
	stream, err := e.client.IngestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		if err := stream.Send(logEvent("agent-a", seq)); err != nil {
			t.Fatal(err)
		}
	}
	for seq := uint64(1); seq <= 3; seq++ {
		ack, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if seq <= 2 && !ack.Accepted {
			t.Fatalf("event %d rejected: %s", seq, ack.Error)
		}
		if seq == 3 {
			if ack.Accepted || !ack.Retryable || ack.RetryAfterMs == 0 || !strings.Contains(ack.Error, engine.ReasonAgentEvents) {
				t.Fatalf("over-quota ack = %+v", ack)
			}
		}
	}
	// Another agent is unaffected (the agent check is skipped without authz).
	if err := stream.Send(logEvent("agent-b", 1)); err != nil {
		t.Fatal(err)
	}
	if ack, err := stream.Recv(); err != nil || !ack.Accepted {
		t.Fatalf("agent-b: %+v %v", ack, err)
	}
	if u := e.eng.Usage(); u.UnanchoredEvents != 3 || u.Rejected[engine.ReasonAgentEvents] != 1 {
		t.Fatalf("usage = %+v", u)
	}
	// Anchor agent-a's epoch: the re-sent event is accepted.
	if err := e.eng.SealAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	jobs := e.sink.jobs
	e.sink.mu.Unlock()
	for _, j := range jobs { // one epoch per agent
		if err := j.Done(context.Background(), anchor.Result{EpochID: 1, TxHash: "0xfeed", BlockNumber: 9}); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.Send(logEvent("agent-a", 3)); err != nil {
		t.Fatal(err)
	}
	if ack, err := stream.Recv(); err != nil || !ack.Accepted {
		t.Fatalf("re-sent event: %+v %v", ack, err)
	}
	stream.CloseSend()
}
