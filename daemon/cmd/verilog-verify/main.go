// Command verilog-verify checks logged events against the Merkle roots and
// agent keys recorded on chain, and exports events and proofs from evidence
// bundles.
//
// Single-event mode: an event file holding exactly the canonical event bytes
// (one trailing newline allowed), inclusion in the anchored epoch, a valid
// agent signature, and a well-formed signing key registered and valid at the
// anchor time.
//
//	verilog-verify --event event.json --proof proof.json --epoch N \
//	    --agent-id ID --rpc URL --contract 0xADDR --chain-id N [--finality finalized]
//
// Run mode: the complete evidence of the agent (a bundle for every anchored
// epoch, each rebuilding its on-chain root and count), every event of the run
// as above (the earliest valid anchored copy of an event decides), plus the
// run's hash chain (contiguous from step 1, no forks, epochs in chain order)
// and a terminal run_end event.
//
//	verilog-verify --run-id RUN --bundles DIR --agent-id ID --rpc URL --contract 0xADDR --chain-id N
//
// --chain-id is required: the endpoint's eth_chainId must match it. Every
// read is pinned to the final block under --finality (finalized, safe,
// latest or depth:N; default finalized), printed on stderr. An epoch anchored
// at the head but not final yet is "not anchored yet" (exit 2); in run mode
// the verdict covers the final epochs, and a non-final epoch holding events
// of the run makes the run not anchored yet (exit 2).
//
// stdout is exactly one verdict line:
//
//	[SUCCESS] Log Integrity Verified                         (exit 0)
//	[FAILURE] Tampered Log Detected                          (exit 1)
//	[SUCCESS-INCOMPLETE] Log Integrity Verified, Run Incomplete  (exit 3, run mode
//	    with --allow-incomplete only: every event present verifies, but the run
//	    has no run_end, so truncation cannot be ruled out)
//
// Exit status 2 means no verdict could be reached (bad arguments, files that
// cannot be read, RPC failure, chain id mismatch, evidence not final yet);
// nothing is printed on stdout. A defect in the
// evidence itself (an unanchored epoch, a malformed event or bundle, missing
// epochs) is a FAILURE, never exit 2.
//
//	verilog-verify export --bundle FILE (--index I | --digest 0x...) --out DIR
//	verilog-verify export --daemon HOST:PORT --agent-id ID --epoch N (--index I | --digest 0x...) --out DIR \
//	    --daemon-ca ca.pem --daemon-cert client.pem --daemon-key client-key.pem
//
// Before registering an agent key, the key admin checks it:
//
//	verilog-verify keycheck --agent-id ID --pubkey 0x... --pop 0x...
//
// which accepts only a safe Ed25519 key (canonical, prime order) with a valid
// proof of possession for the agent id (exit 0: "[KEY OK] ...", exit 1:
// "[KEY REJECTED] ...", exit 2: bad arguments).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	verilogv1 "github.com/ronitspatil/verilog/daemon/gen/verilog/v1"
	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/finality"
	"github.com/ronitspatil/verilog/daemon/internal/merkle"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/verify"
)

const (
	successLine    = "[SUCCESS] Log Integrity Verified"
	failureLine    = "[FAILURE] Tampered Log Detected"
	incompleteLine = "[SUCCESS-INCOMPLETE] Log Integrity Verified, Run Incomplete"

	exitVerified    = 0
	exitTampered    = 1
	exitOperational = 2
	exitIncomplete  = 3
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
	if len(args) > 0 && args[0] == "keycheck" {
		return runKeycheck(args[1:], stdout, stderr)
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
	allowIncomplete := fs.Bool("allow-incomplete", false, "run mode: accept a run without run_end with the distinct verdict [SUCCESS-INCOMPLETE], exit 3 (investigations only)")
	agentID := fs.String("agent-id", "", "agent id string, or 0x-prefixed bytes32 agent key (required)")
	rpcURL := fs.String("rpc", os.Getenv("VERILOG_RPC_URL"), "EVM JSON-RPC endpoint (env VERILOG_RPC_URL)")
	contract := fs.String("contract", os.Getenv("VERILOG_CONTRACT"), "VeriLogRegistry address (env VERILOG_CONTRACT)")
	onchain := fs.Bool("onchain-check", true, "also evaluate each proof with the contract's verifyAnchoredLeaf")
	timeout := fs.Duration("timeout", 30*time.Second, "RPC timeout")
	chainIDFlag := fs.String("chain-id", os.Getenv("VERILOG_CHAIN_ID"), "required: the chain id the registry lives on; a different eth_chainId is exit 2 (env VERILOG_CHAIN_ID)")
	finalityFlag := fs.String("finality", "finalized", "block every read is pinned to: finalized, safe, latest or depth:N; an epoch not final there is \"not anchored yet\" (exit 2)")
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
	case *chainIDFlag == "":
		return operational("--chain-id (or VERILOG_CHAIN_ID) is required: a verdict is only meaningful for the chain the registry lives on")
	}
	wantChainID, ok := new(big.Int).SetString(*chainIDFlag, 10)
	if !ok || wantChainID.Sign() <= 0 {
		return operational("--chain-id must be a positive decimal number")
	}
	mode, err := finality.Parse(*finalityFlag)
	if err != nil {
		return operational("--finality: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var (
		evidence     []verify.EpochEvidence
		loadWarnings []string
		eventJSON    []byte
		proof        []merkle.Hash
	)
	if runMode {
		var err error
		if evidence, loadWarnings, err = loadEvidence(*bundlesDir); err != nil {
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
	point, err := pinChain(ctx, client, wantChainID, mode)
	if err != nil {
		return operational("%v", err)
	}
	fmt.Fprintf(stderr, "chain:          id %s, verdict at block %s (%s, finality %s)\n", wantChainID, point.Number, point.Hash().Hex(), mode)
	v, err := verify.NewAt(ctx, client, common.HexToAddress(*contract), *onchain, point.Number)
	if err != nil {
		return operational("%v", err)
	}
	// The pinned block must still be the canonical one once every read is done.
	pinned := func() error { return stillCanonical(ctx, client, point) }

	if runMode {
		rep, err := v.Run(ctx, verify.RunInput{AgentID: *agentID, RunID: *runID, Epochs: evidence, AllowIncomplete: *allowIncomplete})
		if err == nil {
			err = pinned()
		}
		if err != nil {
			return operational("%v", err)
		}
		fmt.Fprintf(stderr, "agent key:      %s\n", rep.AgentKey.Hex())
		fmt.Fprintf(stderr, "run id:         %s\n", rep.RunID)
		fmt.Fprintf(stderr, "evidence:       %d epochs anchored for the agent\n", rep.AgentEpochs)
		if rep.Events > 0 {
			fmt.Fprintf(stderr, "events:         %d (last step %d) in epochs %v\n", rep.Events, rep.LastStep, rep.Epochs)
		}
		if rep.SDKDropped > 0 {
			fmt.Fprintf(stderr, "sdk dropped:    %d events (self-reported by the agent SDK, not tampering)\n", rep.SDKDropped)
		}
		if rep.EndStatus != "" {
			fmt.Fprintf(stderr, "run_end:        status %q\n", rep.EndStatus)
		}
		for _, w := range append(loadWarnings, rep.Warnings...) {
			fmt.Fprintf(stderr, "warning:        %s\n", w)
		}
		switch {
		case !rep.Verified:
			fmt.Fprintf(stderr, "reason:         %s\n", rep.Reason)
			fmt.Fprintln(stdout, failureLine)
			return exitTampered
		case rep.Incomplete:
			fmt.Fprintln(stdout, incompleteLine)
			return exitIncomplete
		}
		fmt.Fprintln(stdout, successLine)
		return exitVerified
	}

	rep, err := v.Event(ctx, eventJSON, proof, *epoch, *agentID)
	if err == nil {
		err = pinned()
	}
	if err != nil {
		return operational("%v", err)
	}
	fmt.Fprintf(stderr, "agent key:      %s\n", rep.AgentKey.Hex())
	if rep.AnchoredAt.IsZero() {
		fmt.Fprintf(stderr, "epoch:          %d (not anchored)\n", *epoch)
	} else {
		fmt.Fprintf(stderr, "epoch:          %d (anchored %s)\n", *epoch, rep.AnchoredAt.Format(time.RFC3339))
		fmt.Fprintf(stderr, "on-chain root:  %s\n", rep.OnChainRoot.Hex())
	}
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
	if rep.Canonical != nil {
		fmt.Fprintf(stderr, "signed bytes:   %s\n", rep.Canonical)
	}
	if !rep.Verified {
		fmt.Fprintf(stderr, "reason:         %s\n", rep.Reason)
		fmt.Fprintln(stdout, failureLine)
		return exitTampered
	}
	fmt.Fprintln(stdout, successLine)
	return exitVerified
}

// chainReader is what pinChain needs (*ethclient.Client implements it).
type chainReader interface {
	ChainID(ctx context.Context) (*big.Int, error)
	finality.HeaderReader
}

// pinChain checks that the endpoint serves chain want and returns the final
// block under mode, to which every read is pinned.
func pinChain(ctx context.Context, c chainReader, want *big.Int, mode finality.Mode) (*types.Header, error) {
	got, err := c.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading eth_chainId: %v", err)
	}
	if got.Cmp(want) != 0 {
		return nil, fmt.Errorf("the RPC endpoint serves chain id %s, not --chain-id %s: wrong endpoint or wrong chain", got, want)
	}
	return mode.Check(ctx, c)
}

// stillCanonical checks that the pinned block is still the canonical one
// once every read is done (a reorg deeper than the finality rule would
// change the answer).
func stillCanonical(ctx context.Context, c finality.HeaderReader, point *types.Header) error {
	h, err := c.HeaderByNumber(ctx, point.Number)
	if err != nil {
		return fmt.Errorf("re-reading block %s: %v", point.Number, err)
	}
	if h.Hash() != point.Hash() {
		return fmt.Errorf("block %s was reorganized during verification (%s, now %s); retry, or use a stronger --finality",
			point.Number, point.Hash().Hex(), h.Hash().Hex())
	}
	return nil
}

// loadEvidence reads every evidence bundle (*.json) under dir. The bundles
// are untrusted: run mode checks each against the chain. A file that cannot
// be read is an operational error; a file that is not a bundle is skipped
// with a warning (run mode needs every epoch, so skipping can never hide one).
func loadEvidence(dir string) ([]verify.EpochEvidence, []string, error) {
	files, warnings, err := readBundles(dir)
	if err != nil {
		return nil, nil, err
	}
	out := make([]verify.EpochEvidence, len(files))
	for i, f := range files {
		out[i] = f.evidence(f.path)
	}
	return out, warnings, nil
}

// bundleFile is one evidence bundle as read from disk.
type bundleFile struct {
	path   string // as found under the directory
	rel    string // relative to the directory, slash-separated
	data   []byte // the file's exact bytes
	bundle store.Bundle
}

// evidence returns the bundle's content for the verifier, labelled source.
func (f bundleFile) evidence(source string) verify.EpochEvidence {
	e := verify.EpochEvidence{Source: source, EpochID: f.bundle.EpochID, Events: make([][]byte, len(f.bundle.Events))}
	if k, err := canonical.ParseDigest(f.bundle.AgentKey); err == nil {
		e.AgentKey = &k
	}
	for i, ev := range f.bundle.Events {
		e.Events[i] = []byte(ev.CanonicalEvent)
	}
	return e
}

// readBundles reads every *.json under dir, in lexical order; files that
// are not bundles are skipped with a warning.
func readBundles(dir string) ([]bundleFile, []string, error) {
	var out []bundleFile
	var warnings []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		var b store.Bundle
		if err := json.Unmarshal(data, &b); err != nil || b.EpochID == 0 {
			warnings = append(warnings, fmt.Sprintf("ignored %s: not an evidence bundle", path))
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, bundleFile{path: path, rel: filepath.ToSlash(rel), data: data, bundle: b})
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("--bundles: %w", err)
	}
	return out, warnings, nil
}

// runKeycheck checks a key before the key admin registers it on chain.
func runKeycheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verilog-verify keycheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agentID := fs.String("agent-id", "", "agent id string, or 0x-prefixed bytes32 agent key (required)")
	pubHex := fs.String("pubkey", "", "0x-hex Ed25519 public key to register (required)")
	popHex := fs.String("pop", "", "0x-hex proof-of-possession signature printed by keygen (required)")
	if err := fs.Parse(args); err != nil {
		return exitOperational
	}
	if *agentID == "" || *pubHex == "" || *popHex == "" || fs.NArg() > 0 {
		fs.Usage()
		fmt.Fprintln(stderr, "error: --agent-id, --pubkey and --pop are required")
		return exitOperational
	}
	agentKey, _, err := verify.AgentKey(*agentID)
	if err != nil {
		fmt.Fprintln(stderr, "error: --agent-id:", err)
		return exitOperational
	}
	pub, err1 := decodeHex(*pubHex)
	pop, err2 := decodeHex(*popHex)
	if err1 != nil || err2 != nil {
		fmt.Fprintln(stderr, "error: --pubkey and --pop must be 0x-prefixed hex")
		return exitOperational
	}
	if err := canonical.CheckKeyRegistration(agentKey, pub, pop); err != nil {
		fmt.Fprintf(stdout, "[KEY REJECTED] %v\n", err)
		fmt.Fprintln(stderr, "do not register this key")
		return exitTampered
	}
	fmt.Fprintln(stdout, "[KEY OK] Safe Ed25519 key with a valid proof of possession")
	fmt.Fprintf(stderr, "agent key: %s\nkey id:    %s\nregister (as KEY_ADMIN_ROLE):\n  cast send <REGISTRY> 'registerAgentKey(bytes32,bytes32)' %s %s --rpc-url <RPC> <key-admin signer>\n",
		agentKey.Hex(), canonical.KeyID(pub).Hex(), agentKey.Hex(), "0x"+hex.EncodeToString(pub))
	return exitVerified
}

func decodeHex(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, errors.New("missing 0x prefix")
	}
	return hex.DecodeString(s[2:])
}

func runExport(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("verilog-verify export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	bundlePath := fs.String("bundle", "", "evidence bundle file (data-dir/evidence/<agentKey>/epoch-N.json)")
	daemon := fs.String("daemon", "", "verilogd gRPC address, to fetch the proof with GetProof instead of reading a bundle")
	daemonCA := fs.String("daemon-ca", "", "PEM CA certificate of the daemon's server certificate (system roots if unset)")
	daemonCert := fs.String("daemon-cert", "", "PEM client certificate for --daemon (mTLS): an auditor's, or the agent's own")
	daemonKey := fs.String("daemon-key", "", "PEM private key of --daemon-cert")
	daemonInsecure := fs.Bool("daemon-insecure", false, "DEV ONLY: connect to --daemon over plaintext")
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
		meta = fmt.Sprintf("--epoch %d --agent-id %q --contract %s --chain-id %s", b.EpochID, b.AgentID, b.Contract, b.ChainID)
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
		creds, err := daemonCreds(*daemonCA, *daemonCert, *daemonKey, *daemonInsecure, stderr)
		if err != nil {
			return err
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

// daemonCreds returns the transport credentials for export --daemon: mutual
// TLS (TLS 1.3) by default, plaintext only when asked for explicitly.
func daemonCreds(caFile, certFile, keyFile string, plaintext bool, stderr io.Writer) (credentials.TransportCredentials, error) {
	if plaintext {
		if caFile != "" || certFile != "" || keyFile != "" {
			return nil, errors.New("--daemon-insecure cannot be combined with --daemon-ca, --daemon-cert or --daemon-key")
		}
		fmt.Fprintln(stderr, "warning: --daemon-insecure: connecting over plaintext (development only)")
		return insecure.NewCredentials(), nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("--daemon-ca: %w", err)
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("--daemon-ca: no PEM certificates found")
		}
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("--daemon-cert and --daemon-key must be set together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("--daemon-cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return credentials.NewTLS(cfg), nil
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
