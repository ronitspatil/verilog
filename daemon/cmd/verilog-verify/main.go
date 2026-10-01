// Command verilog-verify checks logged events against the Merkle roots and
// agent keys recorded on chain, and exports events and proofs from evidence
// bundles.
//
// Single-event mode: inclusion in the anchored epoch, a valid agent
// signature, and a signing key registered and valid at the anchor time.
//
//	verilog-verify --event event.json --proof proof.json --epoch N \
//	    --agent-id ID --rpc URL --contract 0xADDR
//
// Run mode: every event of the run as above, plus the run's hash chain
// (contiguous from step 1, no forks, epochs in chain order) and a terminal
// run_end event (--allow-incomplete accepts a missing run_end with a warning).
//
//	verilog-verify --run-id RUN --bundles DIR --agent-id ID --rpc URL --contract 0xADDR
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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
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
	eventPath := fs.String("event", "", "raw JSON event file (single-event mode)")
	proofPath := fs.String("proof", "", "JSON array of 0x-hex Merkle proof hashes (single-event mode)")
	epoch := fs.Uint64("epoch", 0, "on-chain epoch id (single-event mode)")
	runID := fs.String("run-id", "", "verify a whole run (run mode, with --bundles)")
	bundlesDir := fs.String("bundles", "", "directory of evidence bundles, searched recursively (run mode)")
	allowIncomplete := fs.Bool("allow-incomplete", false, "run mode: accept a run without run_end, with a warning (investigations only)")
	agentID := fs.String("agent-id", "", "agent id string, or 0x-prefixed bytes32 agent key (required)")
	rpcURL := fs.String("rpc", os.Getenv("VERILOG_RPC_URL"), "EVM JSON-RPC endpoint (env VERILOG_RPC_URL)")
	contract := fs.String("contract", os.Getenv("VERILOG_CONTRACT"), "VeriLogRegistry address (env VERILOG_CONTRACT)")
	onchain := fs.Bool("onchain-check", true, "also evaluate each proof with the contract's verifyAnchoredLeaf")
	timeout := fs.Duration("timeout", 30*time.Second, "RPC timeout")
	if err := fs.Parse(args); err != nil {
		return exitOperational
	}
	operational := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return exitOperational
	}
	runMode := *runID != "" || *bundlesDir != ""
	switch {
	case *agentID == "" || *rpcURL == "":
		fs.Usage()
		return operational("--agent-id and --rpc are required")
	case runMode && (*runID == "" || *bundlesDir == ""):
		return operational("run mode needs both --run-id and --bundles")
	case runMode && (*eventPath != "" || *proofPath != "" || *epoch != 0):
		return operational("--event/--proof/--epoch and --run-id/--bundles are exclusive")
	case !runMode && (*eventPath == "" || *proofPath == "" || *epoch == 0):
		fs.Usage()
		return operational("--event, --proof and --epoch are required (or --run-id and --bundles for run mode)")
	case !runMode && *allowIncomplete:
		return operational("--allow-incomplete only applies to run mode")
	case !common.IsHexAddress(*contract):
		return operational("--contract must be a 0x address")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var (
		evidence  []verify.Evidence
		eventJSON []byte
		proof     []merkle.Hash
	)
	if runMode {
		var err error
		if evidence, err = loadEvidence(*bundlesDir); err != nil {
			return operational("%v", err)
		}
	} else {
		var err error
		if eventJSON, err = os.ReadFile(*eventPath); err != nil {
			return operational("reading event file: %v", err)
		}
		proofJSON, err := os.ReadFile(*proofPath)
		if err != nil {
			return operational("reading proof file: %v", err)
		}
		if proof, err = verify.ParseProof(proofJSON); err != nil {
			return operational("%v", err)
		}
	}

	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		return operational("dialing RPC: %v", err)
	}
	defer client.Close()
	v, err := verify.New(ctx, client, common.HexToAddress(*contract), *onchain)
	if err != nil {
		return operational("%v", err)
	}

	if runMode {
		rep, err := v.Run(ctx, verify.RunInput{AgentID: *agentID, RunID: *runID, Evidence: evidence, AllowIncomplete: *allowIncomplete})
		if err != nil {
			return operational("%v", err)
		}
		fmt.Fprintf(stderr, "agent key:      %s\n", rep.AgentKey.Hex())
		fmt.Fprintf(stderr, "run id:         %s\n", rep.RunID)
		fmt.Fprintf(stderr, "events:         %d (last step %d) in epochs %v\n", rep.Events, rep.LastStep, rep.Epochs)
		if rep.SDKDropped > 0 {
			fmt.Fprintf(stderr, "sdk dropped:    %d events (self-reported by the agent SDK, not tampering)\n", rep.SDKDropped)
		}
		if rep.EndStatus != "" {
			fmt.Fprintf(stderr, "run_end:        status %q\n", rep.EndStatus)
		}
		if rep.Warning != "" {
			fmt.Fprintf(stderr, "warning:        %s\n", rep.Warning)
		}
		if !rep.Verified {
			fmt.Fprintf(stderr, "reason:         %s\n", rep.Reason)
			fmt.Fprintln(stdout, failureLine)
			return exitTampered
		}
		fmt.Fprintln(stdout, successLine)
		return exitVerified
	}

	rep, err := v.Event(ctx, eventJSON, proof, *epoch, *agentID)
	if err != nil {
		return operational("%v", err)
	}
	fmt.Fprintf(stderr, "agent key:      %s\n", rep.AgentKey.Hex())
	fmt.Fprintf(stderr, "epoch:          %d (anchored %s)\n", *epoch, rep.AnchoredAt.Format(time.RFC3339))
	fmt.Fprintf(stderr, "on-chain root:  %s\n", rep.OnChainRoot.Hex())
	if rep.ContentDigest != (canonical.Digest{}) {
		fmt.Fprintf(stderr, "content digest: %s\n", rep.ContentDigest.Hex())
		fmt.Fprintf(stderr, "leaf:           %s\n", rep.Leaf.Hex())
		fmt.Fprintf(stderr, "computed root:  %s\n", rep.ComputedRoot.Hex())
	}
	if rep.RunID != "" {
		fmt.Fprintf(stderr, "run id / step:  %s / %d (%s)\n", rep.RunID, rep.StepNumber, rep.EventType)
		fmt.Fprintf(stderr, "key id:         %s\n", rep.KeyID.Hex())
	}
	if rep.KeyStatus != "" {
		fmt.Fprintf(stderr, "signing key:    %s\n", rep.KeyStatus)
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

// loadEvidence reads every evidence bundle (*.json) under dir. The bundles
// are untrusted: each event is checked against the chain.
func loadEvidence(dir string) ([]verify.Evidence, error) {
	var out []verify.Evidence
	n := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		b, err := store.ReadBundleFile(path)
		if err != nil {
			return fmt.Errorf("reading bundle: %w", err)
		}
		n++
		for _, e := range b.Events {
			proof := make([]merkle.Hash, len(e.Proof))
			for i, p := range e.Proof {
				d, err := canonical.ParseDigest(p)
				if err != nil {
					return fmt.Errorf("%s: proof of leaf %d: %w", path, e.LeafIndex, err)
				}
				proof[i] = d
			}
			out = append(out, verify.Evidence{EpochID: b.EpochID, EventJSON: []byte(e.CanonicalEvent), Proof: proof})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("--bundles: %w", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("--bundles: no evidence bundles (*.json) under %s", dir)
	}
	return out, nil
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
