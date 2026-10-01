// Command verilog-verify checks one logged event against the Merkle root
// anchored on chain, and exports events and proofs from evidence bundles.
//
//	verilog-verify --event event.json --proof proof.json --epoch N \
//	    --agent-id ID --rpc URL --contract 0xADDR
//
// stdout is exactly one verdict line:
//
//	[SUCCESS] Log Integrity Verified   (exit 0)
//	[FAILURE] Tampered Log Detected    (exit 1)
//
// Exit status 2 means no verdict could be reached (bad arguments, unreadable
// files, RPC failure, epoch not anchored); nothing is printed on stdout.
//
//	verilog-verify export --bundle FILE (--index I | --digest 0x...) --out DIR
//	verilog-verify export --daemon HOST:PORT --agent-id ID --epoch N (--index I | --digest 0x...) --out DIR
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/verify"
)

const (
	successLine = "[SUCCESS] Log Integrity Verified"
	failureLine = "[FAILURE] Tampered Log Detected"

	exitVerified    = 0
	exitTampered    = 1
	exitOperational = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "export" {
		if err := runExport(args[1:], stderr); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitOperational
		}
		return 0
	}
	if len(args) > 0 && args[0] == "verify" {
		args = args[1:]
	}
	return runVerify(args, stdout, stderr)
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verilog-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	eventPath := fs.String("event", "", "raw JSON event file (required)")
	proofPath := fs.String("proof", "", "JSON array of 0x-hex Merkle proof hashes (required)")
	epoch := fs.Uint64("epoch", 0, "on-chain epoch id (required)")
	agentID := fs.String("agent-id", "", "agent id string, or 0x-prefixed bytes32 agent key (required)")
	rpcURL := fs.String("rpc", os.Getenv("VERILOG_RPC_URL"), "EVM JSON-RPC endpoint (env VERILOG_RPC_URL)")
	contract := fs.String("contract", os.Getenv("VERILOG_CONTRACT"), "VeriLogRegistry address (env VERILOG_CONTRACT)")
	onchain := fs.Bool("onchain-check", true, "also evaluate the proof with the contract's verifyAnchoredLeaf")
	timeout := fs.Duration("timeout", 30*time.Second, "RPC timeout")
	if err := fs.Parse(args); err != nil {
		return exitOperational
	}
	operational := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return exitOperational
	}
	switch {
	case *eventPath == "" || *proofPath == "" || *epoch == 0 || *agentID == "" || *rpcURL == "":
		fs.Usage()
		return operational("--event, --proof, --epoch, --agent-id and --rpc are required")
	case !common.IsHexAddress(*contract):
		return operational("--contract must be a 0x address")
	}
	eventJSON, err := os.ReadFile(*eventPath)
	if err != nil {
		return operational("reading event file: %v", err)
	}
	proofJSON, err := os.ReadFile(*proofPath)
	if err != nil {
		return operational("reading proof file: %v", err)
	}
	proof, err := verify.ParseProof(proofJSON)
	if err != nil {
		return operational("%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		return operational("dialing RPC: %v", err)
	}
	defer client.Close()

	rep, err := verify.Verify(ctx, client, verify.Input{
		EventJSON:    eventJSON,
		Proof:        proof,
		EpochID:      *epoch,
		AgentID:      *agentID,
		Contract:     common.HexToAddress(*contract),
		OnChainCheck: *onchain,
	})
	if err != nil {
		var oe *verify.OperationalError
		if errors.As(err, &oe) {
			return operational("%v", oe)
		}
		return operational("%v", err)
	}

	fmt.Fprintf(stderr, "agent key:      %s\n", rep.AgentKey.Hex())
	fmt.Fprintf(stderr, "epoch:          %d\n", *epoch)
	fmt.Fprintf(stderr, "on-chain root:  %s\n", rep.OnChainRoot.Hex())
	if rep.ContentDigest != (canonical.Digest{}) {
		fmt.Fprintf(stderr, "content digest: %s\n", rep.ContentDigest.Hex())
		fmt.Fprintf(stderr, "leaf:           %s\n", rep.Leaf.Hex())
		fmt.Fprintf(stderr, "computed root:  %s\n", rep.ComputedRoot.Hex())
	}
	fmt.Fprintf(stderr, "on-chain check: %s\n", rep.OnChainCheck)
	if !rep.Verified {
		fmt.Fprintf(stderr, "reason:         %s\n", rep.Reason)
		fmt.Fprintln(stdout, failureLine)
		return exitTampered
	}
	fmt.Fprintln(stdout, successLine)
	return exitVerified
}

func runExport(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("verilog-verify export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "evidence bundle file (data-dir/evidence/<agentKey>/epoch-N.json)")
	daemon := fs.String("daemon", "", "verilogd gRPC address, to fetch the proof with GetProof instead of reading a bundle")
	daemonCA := fs.String("daemon-ca", "", "PEM CA certificate to connect to --daemon over TLS (plaintext if unset)")
	agentID := fs.String("agent-id", "", "agent id (with --daemon)")
	epoch := fs.Uint64("epoch", 0, "epoch id (with --daemon)")
	index := fs.Int("index", -1, "leaf index of the event")
	digest := fs.String("digest", "", "content digest (0x-hex) of the event, instead of --index")
	outDir := fs.String("out", ".", "directory for event.json and proof.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*index < 0) == (*digest == "") {
		return errors.New("exactly one of --index or --digest is required")
	}

	var eventJSON string
	var proof []string
	var meta string
	switch {
	case *bundlePath != "" && *daemon == "":
		b, err := store.ReadBundleFile(*bundlePath)
		if err != nil {
			return err
		}
		var ev *store.EventProof
		for i := range b.Events {
			if (*index >= 0 && b.Events[i].LeafIndex == *index) || (*digest != "" && equalHex(b.Events[i].ContentDigest, *digest)) {
				ev = &b.Events[i]
				break
			}
		}
		if ev == nil {
			return errors.New("event not found in bundle")
		}
		eventJSON, proof = ev.CanonicalEvent, ev.Proof
		meta = fmt.Sprintf("--epoch %d --agent-id %q --contract %s", b.EpochID, b.AgentID, b.Contract)
	case *daemon != "" && *bundlePath == "":
		if *agentID == "" || *epoch == 0 {
			return errors.New("--agent-id and --epoch are required with --daemon")
		}
		req := &verilogv1.GetProofRequest{AgentId: *agentID, EpochId: *epoch}
		if *index >= 0 {
			req.Selector = &verilogv1.GetProofRequest_LeafIndex{LeafIndex: uint64(*index)}
		} else {
			d, err := canonical.ParseDigest(*digest)
			if err != nil {
				return fmt.Errorf("--digest: %w", err)
			}
			req.Selector = &verilogv1.GetProofRequest_ContentDigest{ContentDigest: d[:]}
		}
		creds := insecure.NewCredentials()
		if *daemonCA != "" {
			tlsCreds, err := credentials.NewClientTLSFromFile(*daemonCA, "")
			if err != nil {
				return fmt.Errorf("--daemon-ca: %w", err)
			}
			creds = tlsCreds
		}
		conn, err := grpc.NewClient(*daemon, grpc.WithTransportCredentials(creds))
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resp, err := verilogv1.NewVeriLogClient(conn).GetProof(ctx, req)
		if err != nil {
			return err
		}
		eventJSON = resp.CanonicalEventJson
		for _, p := range resp.Proof {
			var h canonical.Digest
			copy(h[:], p)
			proof = append(proof, h.Hex())
		}
		meta = fmt.Sprintf("--epoch %d --agent-id %q", resp.EpochId, resp.AgentId)
	default:
		return errors.New("exactly one of --bundle or --daemon is required")
	}
	if proof == nil {
		proof = []string{}
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	eventOut := filepath.Join(*outDir, "event.json")
	proofOut := filepath.Join(*outDir, "proof.json")
	if err := os.WriteFile(eventOut, []byte(eventJSON+"\n"), 0o644); err != nil {
		return err
	}
	pj, err := marshalProof(proof)
	if err != nil {
		return err
	}
	if err := os.WriteFile(proofOut, pj, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "wrote %s and %s\nverify with: verilog-verify --event %s --proof %s %s --rpc <RPC_URL>\n",
		eventOut, proofOut, eventOut, proofOut, meta)
	return nil
}

func equalHex(a, b string) bool {
	da, err1 := canonical.ParseDigest(a)
	db, err2 := canonical.ParseDigest(b)
	return err1 == nil && err2 == nil && da == db
}

func marshalProof(p []string) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
