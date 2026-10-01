package anchor

import (
	"context"
	"sync"
	"testing"
	"time"
)

// M6: a backlog of one agent's epochs does not hold up another agent's.
// Agents are served in turn, each agent's epochs oldest first, and jobs
// complete in the order they were sent.
func TestWorkerServesAgentsInTurn(t *testing.T) {
	chain := &flakyChain{}
	w := NewWorker(chain, WorkerOptions{Backoff: Backoff{Initial: time.Millisecond, Max: time.Millisecond}}, nil)
	flood, other, third := [32]byte{0xf}, [32]byte{0xa}, [32]byte{0xb}
	var mu sync.Mutex
	var done []Request
	all := make(chan struct{})
	enqueue := func(agent [32]byte, n byte) {
		req := Request{AgentKey: agent, Root: [32]byte{agent[0], n}, Count: 1}
		w.Enqueue(Job{Request: req, Done: func(context.Context, Result) error {
			mu.Lock()
			defer mu.Unlock()
			done = append(done, req)
			if len(done) == 14 {
				close(all)
			}
			return nil
		}})
	}
	for i := byte(1); i <= 10; i++ {
		enqueue(flood, i)
	}
	enqueue(other, 1)
	enqueue(other, 2)
	enqueue(third, 1)
	enqueue(third, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	select {
	case <-all:
	case <-time.After(5 * time.Second):
		t.Fatal("jobs did not complete")
	}
	chain.mu.Lock()
	defer chain.mu.Unlock()
	pos := map[[32]byte]int{}
	for i, r := range chain.calls {
		if _, ok := pos[r.Root]; !ok {
			pos[r.Root] = i
		}
	}
	// Both other agents' epochs are sent within the first 6 anchors, not
	// after the flooding agent's 10.
	for _, r := range [][32]byte{{0xa, 1}, {0xa, 2}, {0xb, 1}, {0xb, 2}} {
		if pos[r] >= 6 {
			t.Fatalf("epoch %x sent at position %d; calls %v", r[:2], pos[r], roots(chain.calls))
		}
	}
	// Each agent's epochs in order, and completion order = send order.
	last := map[[32]byte]byte{}
	for i, r := range done {
		if r.Root[1] <= last[r.AgentKey] {
			t.Fatalf("agent %x epochs out of order: %v", r.AgentKey[:1], roots(done))
		}
		last[r.AgentKey] = r.Root[1]
		if r.Root != chain.calls[i].Root {
			t.Fatalf("completed %v, sent %v", roots(done), roots(chain.calls))
		}
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if st := w.Stats(); st.Queued == 0 && st.Mined == 0 && st.FinalityLag == 0 {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("stats after drain: %+v", st)
		}
	}
}

func roots(reqs []Request) [][2]byte {
	out := make([][2]byte, len(reqs))
	for i, r := range reqs {
		out[i] = [2]byte{r.Root[0], r.Root[1]}
	}
	return out
}
