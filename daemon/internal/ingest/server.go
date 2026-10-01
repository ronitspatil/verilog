// Package ingest implements the VeriLog gRPC service.
//
// IngestStream is pipelined: a receive loop validates, canonicalizes and
// hashes each event and submits it to the engine without waiting for it to be
// durable, while a send loop resolves the submissions in order and writes one
// Ack per event. Up to Window events per stream can be awaiting durability,
// which lets the engine group-commit many events per fsync even for a single
// client stream.
package ingest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/engine"
	"github.com/ronitspatil/verilog/daemon/internal/store"
)

// Server is the gRPC service implementation.
type Server struct {
	verilogv1.UnimplementedVeriLogServer

	eng             *engine.Engine
	store           *store.Store
	log             *slog.Logger
	maxPayloadBytes int
	window          int
}

// Options configures a Server.
type Options struct {
	MaxPayloadBytes int // reject events whose payload_json is larger
	Window          int // max in-flight (unacked) events per stream
}

// NewServer returns a Server.
func NewServer(eng *engine.Engine, st *store.Store, opts Options, logger *slog.Logger) *Server {
	if opts.MaxPayloadBytes <= 0 {
		opts.MaxPayloadBytes = 1 << 20
	}
	if opts.Window <= 0 {
		opts.Window = 1024
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{eng: eng, store: st, log: logger, maxPayloadBytes: opts.MaxPayloadBytes, window: opts.Window}
}

type inflight struct {
	seq    uint64
	ack    *verilogv1.Ack       // set when the event was rejected before submission
	result <-chan engine.Result // set when submitted
	prep   engine.Prepared
}

// IngestStream receives events and answers each with an Ack, in order.
func (s *Server) IngestStream(stream verilogv1.VeriLog_IngestStreamServer) error {
	ctx := stream.Context()
	queue := make(chan inflight, s.window)
	sendErr := make(chan error, 1)

	go func() {
		defer close(sendErr)
		for item := range queue {
			ack := item.ack
			if ack == nil {
				var res engine.Result
				select {
				case res = <-item.result:
				case <-ctx.Done():
					sendErr <- ctx.Err()
					return
				}
				ack = s.resultAck(item, res)
			}
			if err := stream.Send(ack); err != nil {
				sendErr <- err
				return
			}
		}
	}()

	recvErr := s.receive(ctx, stream, queue, sendErr)
	close(queue)
	if err := <-sendErr; err != nil && recvErr == nil {
		recvErr = err
	}
	if recvErr != nil && !errors.Is(recvErr, context.Canceled) {
		s.log.Debug("ingest: stream ended", "err", recvErr)
	}
	return recvErr
}

func (s *Server) receive(ctx context.Context, stream verilogv1.VeriLog_IngestStreamServer, queue chan<- inflight, sendErr <-chan error) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		item := s.prepare(ctx, msg)
		if item.ack == nil && item.result == nil {
			return status.Error(codes.Unavailable, "daemon is shutting down")
		}
		select {
		case queue <- item:
		case err := <-sendErr:
			if err == nil {
				err = io.ErrClosedPipe
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func reject(seq uint64, msg string) *verilogv1.Ack {
	return &verilogv1.Ack{Sequence: seq, Accepted: false, Error: msg}
}

func (s *Server) prepare(ctx context.Context, msg *verilogv1.LogEvent) inflight {
	item := inflight{seq: msg.GetSequence()}
	if len(msg.GetPayloadJson()) > s.maxPayloadBytes {
		item.ack = reject(item.seq, "payload_json exceeds the size limit")
		return item
	}
	if msg.GetTimestampUtc() == nil {
		item.ack = reject(item.seq, "timestamp_utc is required")
		return item
	}
	if err := msg.GetTimestampUtc().CheckValid(); err != nil {
		item.ack = reject(item.seq, "timestamp_utc is invalid: "+err.Error())
		return item
	}
	ev := canonical.Event{
		AgentID:      msg.GetAgentId(),
		StepNumber:   msg.GetStepNumber(),
		EventType:    msg.GetEventType(),
		PayloadJSON:  []byte(msg.GetPayloadJson()),
		TimestampUTC: msg.GetTimestampUtc().AsTime(),
	}
	prep, err := engine.Prepare(ev)
	if err != nil {
		item.ack = reject(item.seq, err.Error())
		return item
	}
	ch, err := s.eng.Submit(ctx, prep)
	if err != nil {
		if errors.Is(err, engine.ErrClosed) {
			return item // neither ack nor result: shutting down
		}
		item.ack = reject(item.seq, "not accepted: "+err.Error())
		return item
	}
	item.result, item.prep = ch, prep
	return item
}

func (s *Server) resultAck(item inflight, res engine.Result) *verilogv1.Ack {
	if res.Err != nil {
		return reject(item.seq, res.Err.Error())
	}
	return &verilogv1.Ack{
		Sequence:      item.seq,
		Accepted:      true,
		ContentDigest: item.prep.Digest[:],
		Leaf:          item.prep.Leaf[:],
		Duplicate:     res.Duplicate,
	}
}

// GetProof returns an inclusion proof from an anchored epoch's evidence bundle.
func (s *Server) GetProof(_ context.Context, req *verilogv1.GetProofRequest) (*verilogv1.GetProofResponse, error) {
	if req.GetAgentId() == "" || req.GetEpochId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "agent_id and epoch_id (>= 1) are required")
	}
	key := canonical.AgentKey(req.GetAgentId())
	b, err := s.store.ReadBundle(key.Hex(), req.GetEpochId())
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "no anchored epoch %d for agent %q (it may not be anchored yet)", req.GetEpochId(), req.GetAgentId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading evidence: %v", err)
	}

	var ev *store.EventProof
	switch sel := req.GetSelector().(type) {
	case *verilogv1.GetProofRequest_LeafIndex:
		if sel.LeafIndex >= uint64(len(b.Events)) {
			return nil, status.Errorf(codes.OutOfRange, "leaf_index %d out of range (epoch has %d events)", sel.LeafIndex, len(b.Events))
		}
		ev = &b.Events[sel.LeafIndex]
	case *verilogv1.GetProofRequest_ContentDigest:
		if len(sel.ContentDigest) != 32 {
			return nil, status.Error(codes.InvalidArgument, "content_digest must be 32 bytes")
		}
		var want canonical.Digest
		copy(want[:], sel.ContentDigest)
		for i := range b.Events {
			if b.Events[i].ContentDigest == want.Hex() {
				ev = &b.Events[i]
				break
			}
		}
		if ev == nil {
			return nil, status.Error(codes.NotFound, "no event with that content digest in this epoch")
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "leaf_index or content_digest is required")
	}

	resp := &verilogv1.GetProofResponse{
		AgentId:            b.AgentID,
		AgentKey:           key[:],
		EpochId:            b.EpochID,
		LeafIndex:          uint64(ev.LeafIndex),
		CanonicalEventJson: ev.CanonicalEvent,
		TxHash:             b.TxHash,
		BlockNumber:        b.BlockNumber,
	}
	var err2 error
	if resp.MerkleRoot, err2 = hexBytes(b.MerkleRoot); err2 != nil {
		return nil, status.Errorf(codes.Internal, "corrupt bundle: %v", err2)
	}
	if resp.Leaf, err2 = hexBytes(ev.Leaf); err2 != nil {
		return nil, status.Errorf(codes.Internal, "corrupt bundle: %v", err2)
	}
	if resp.ContentDigest, err2 = hexBytes(ev.ContentDigest); err2 != nil {
		return nil, status.Errorf(codes.Internal, "corrupt bundle: %v", err2)
	}
	for _, p := range ev.Proof {
		pb, err := hexBytes(p)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "corrupt bundle: %v", err)
		}
		resp.Proof = append(resp.Proof, pb)
	}
	if !bytes.Equal(resp.ContentDigest, digestOf(ev.CanonicalEvent)) {
		return nil, status.Error(codes.DataLoss, "evidence bundle is inconsistent: event does not match its digest")
	}
	return resp, nil
}

func hexBytes(s string) ([]byte, error) {
	d, err := canonical.ParseDigest(s)
	if err != nil {
		return nil, err
	}
	return d[:], nil
}

func digestOf(ev string) []byte {
	d := canonical.ContentDigest([]byte(ev))
	return d[:]
}
