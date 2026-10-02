package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/ronitspatil/verilog/daemon/internal/finality"
	"github.com/ronitspatil/verilog/daemon/internal/redact"
	"github.com/ronitspatil/verilog/daemon/internal/verify"
)

// version is the release version, set at build time with
// -ldflags "-X main.version=v1.2.3"; the git commit comes from the build info.
var version = ""

const reportFormat = "verilog-audit-export/1"

// Report is report.json. Everything but GeneratedAt is a function of the
// evidence and the chain at the verdict block.
type Report struct {
	Format          string        `json:"format"`
	GeneratedAt     string        `json:"generated_at"`
	Tool            Tool          `json:"tool"`
	AgentID         string        `json:"agent_id"`
	AgentKey        string        `json:"agent_key"`
	Window          Window        `json:"window"`
	Chain           Chain         `json:"chain"`
	AllowIncomplete bool          `json:"allow_incomplete"`
	Verdict         string        `json:"verdict"`
	Totals          Totals        `json:"totals"`
	Epochs          []EpochReport `json:"epochs"`
	Runs            []RunReport   `json:"runs"`
	Warnings        []string      `json:"warnings"`
}

// Tool identifies the verifier that produced the report.
type Tool struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Modified bool   `json:"modified"`
}

// Window is the selection of epochs by anchor time.
type Window struct {
	From       string `json:"from"`
	To         string `json:"to"`
	SelectedBy string `json:"selected_by"`
}

// Chain is where and when the verdict was reached.
type Chain struct {
	ChainID            string `json:"chain_id"`
	Registry           string `json:"registry"`
	Finality           string `json:"finality"`
	VerdictBlockNumber uint64 `json:"verdict_block_number"`
	VerdictBlockHash   string `json:"verdict_block_hash"`
	Explorer           string `json:"explorer,omitempty"`
}

// EpochReport is one exported epoch. Root, count and anchor time are read
// from the registry; the anchor transaction and block are as recorded in
// the bundle.
type EpochReport struct {
	Epoch       uint64 `json:"epoch"`
	InWindow    bool   `json:"in_window"`
	Root        string `json:"root"`
	LogCount    uint32 `json:"log_count"`
	AnchoredAt  string `json:"anchored_at"`
	AnchorTx    string `json:"anchor_tx"`
	AnchorBlock uint64 `json:"anchor_block"`
	Bundle      string `json:"bundle"`
	Problem     string `json:"problem,omitempty"`
}

// RunReport is the verdict on one run with events in the window.
type RunReport struct {
	RunID        string   `json:"run_id"`
	Verdict      string   `json:"verdict"`
	Steps        uint64   `json:"steps"`
	RunEndStatus string   `json:"run_end_status"`
	Epochs       []uint64 `json:"epochs"`
	SDKDropped   uint64   `json:"sdk_dropped"`
	Reason       string   `json:"reason,omitempty"`
	Warnings     []string `json:"warnings"`
}

// Totals summarizes the report.
type Totals struct {
	Epochs           int `json:"epochs"`
	EpochsInWindow   int `json:"epochs_in_window"`
	ContextEpochs    int `json:"context_epochs"`
	EventsInWindow   int `json:"events_in_window"`
	EvidenceProblems int `json:"evidence_problems"`
	Runs             int `json:"runs"`
	Success          int `json:"success"`
	Failure          int `json:"failure"`
	Incomplete       int `json:"incomplete"`
	NotFinal         int `json:"not_final"`
}

// exitCode is the export's exit status: 0 when every run in the window is
// SUCCESS, 1 when any run fails or the evidence is defective, 3 when none
// fails but a run is SUCCESS-INCOMPLETE or not final yet (not a full pass).
func (r *Report) exitCode() int {
	switch r.Verdict {
	case verify.VerdictSuccess:
		return exitVerified
	case verify.VerdictFailure:
		return exitTampered
	}
	return exitIncomplete
}

func runAuditExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verilog-verify audit-export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agentID := fs.String("agent-id", "", "agent id string, or 0x-prefixed bytes32 agent key (required)")
	bundlesDir := fs.String("bundles", "", "the agent's evidence directory, searched recursively (required)")
	fromFlag := fs.String("from", "", "start of the window, inclusive: RFC 3339 time or YYYY-MM-DD (UTC); epochs are selected by anchor (block) time (required)")
	toFlag := fs.String("to", "", "end of the window, exclusive: RFC 3339 time or YYYY-MM-DD (UTC) (required)")
	rpcURL := fs.String("rpc", os.Getenv("VERILOG_RPC_URL"), "EVM JSON-RPC endpoint (env VERILOG_RPC_URL)")
	contract := fs.String("contract", os.Getenv("VERILOG_CONTRACT"), "VeriLogRegistry address (env VERILOG_CONTRACT)")
	chainIDFlag := fs.String("chain-id", os.Getenv("VERILOG_CHAIN_ID"), "required: the chain id the registry lives on (env VERILOG_CHAIN_ID)")
	finalityFlag := fs.String("finality", "finalized", "block every read is pinned to: finalized, safe, latest or depth:N")
	allowIncomplete := fs.Bool("allow-incomplete", false, "report a run without run_end as SUCCESS-INCOMPLETE (exit 3) instead of FAILURE")
	explorer := fs.String("explorer", "", "block explorer base URL for links (default: known explorers by chain id)")
	outDir := fs.String("out", "", "output directory; must not exist (required)")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall RPC timeout")
	if err := fs.Parse(args); err != nil {
		return exitOperational
	}
	operational := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "error: "+format+"\n", a...)
		return exitOperational
	}
	switch {
	case fs.NArg() > 0:
		return operational("unexpected argument %q", fs.Arg(0))
	case *agentID == "" || *bundlesDir == "" || *rpcURL == "" || *outDir == "" || *fromFlag == "" || *toFlag == "":
		fs.Usage()
		return operational("--agent-id, --bundles, --from, --to, --rpc and --out are required")
	case !common.IsHexAddress(*contract):
		return operational("--contract must be a 0x address")
	case *chainIDFlag == "":
		return operational("--chain-id (or VERILOG_CHAIN_ID) is required: a verdict is only meaningful for the chain the registry lives on")
	}
	from, err := parseWindowTime(*fromFlag)
	if err != nil {
		return operational("--from: %v", err)
	}
	to, err := parseWindowTime(*toFlag)
	if err != nil {
		return operational("--to: %v", err)
	}
	if !from.Before(to) {
		return operational("--from must be before --to")
	}
	wantChainID, ok := new(big.Int).SetString(*chainIDFlag, 10)
	if !ok || wantChainID.Sign() <= 0 {
		return operational("--chain-id must be a positive decimal number")
	}
	mode, err := finality.Parse(*finalityFlag)
	if err != nil {
		return operational("--finality: %v", err)
	}
	if _, err := os.Lstat(*outDir); err == nil {
		return operational("--out %s already exists", *outDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return operational("--out: %v", err)
	}
	if _, _, err := verify.AgentKey(*agentID); err != nil {
		return operational("--agent-id: %v", err)
	}

	files, loadWarnings, err := readBundles(*bundlesDir)
	if err != nil {
		return operational("%v", err)
	}
	evidence := make([]verify.EpochEvidence, len(files))
	byRel := map[string]bundleFile{}
	for i, f := range files {
		evidence[i] = f.evidence(f.rel)
		byRel[f.rel] = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
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
	v, err := verify.NewAt(ctx, client, common.HexToAddress(*contract), true, point.Number)
	if err != nil {
		return operational("%v", err)
	}
	audit, err := v.Audit(ctx, verify.AuditInput{AgentID: *agentID, From: from, To: to, Evidence: evidence, AllowIncomplete: *allowIncomplete})
	if err == nil {
		err = stillCanonical(ctx, client, point)
	}
	if err != nil {
		return operational("%v", err)
	}

	if *explorer == "" {
		*explorer = knownExplorers[wantChainID.String()]
	}
	rep := buildReport(audit, byRel, loadWarnings, reportParams{
		agentID: *agentID, from: from, to: to, chainID: wantChainID.String(), registry: common.HexToAddress(*contract).Hex(),
		finality: mode.String(), blockNumber: point.Number.Uint64(), blockHash: point.Hash().Hex(), explorer: strings.TrimRight(*explorer, "/"),
		allowIncomplete: *allowIncomplete, generatedAt: time.Now().UTC(), tool: toolInfo(),
	})
	files2, err := renderExport(rep, audit, byRel, redact.URL(*rpcURL))
	if err != nil {
		return operational("%v", err)
	}
	manifestSum, err := writeExport(*outDir, files2)
	if err != nil {
		return operational("%v", err)
	}

	t := rep.Totals
	fmt.Fprintf(stderr, "agent key:      %s\n", rep.AgentKey)
	fmt.Fprintf(stderr, "window:         %s to %s (anchor time)\n", rep.Window.From, rep.Window.To)
	fmt.Fprintf(stderr, "epochs:         %d exported (%d in the window, %d context), %d with evidence problems\n",
		t.Epochs, t.EpochsInWindow, t.ContextEpochs, t.EvidenceProblems)
	fmt.Fprintf(stderr, "runs:           %d (%d SUCCESS, %d FAILURE, %d SUCCESS-INCOMPLETE, %d not final)\n",
		t.Runs, t.Success, t.Failure, t.Incomplete, t.NotFinal)
	for _, r := range rep.Runs {
		if r.Verdict != verify.VerdictSuccess {
			fmt.Fprintf(stderr, "run %s:  %s %s\n", r.RunID, r.Verdict, r.Reason)
		}
	}
	fmt.Fprintf(stderr, "wrote:          %s (MANIFEST.sha256 sha256 %s)\n", *outDir, manifestSum)
	switch code := rep.exitCode(); code {
	case exitVerified:
		fmt.Fprintln(stdout, successLine)
		return code
	case exitTampered:
		fmt.Fprintln(stdout, failureLine)
		return code
	default:
		fmt.Fprintln(stdout, incompleteLine)
		return code
	}
}

// parseWindowTime accepts RFC 3339 or a UTC date (YYYY-MM-DD, midnight).
func parseWindowTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither RFC 3339 nor YYYY-MM-DD", s)
	}
	return t, nil
}

// knownExplorers are block explorers by chain id, for links in the report.
var knownExplorers = map[string]string{
	"1":        "https://etherscan.io",
	"10":       "https://optimistic.etherscan.io",
	"8453":     "https://basescan.org",
	"42161":    "https://arbiscan.io",
	"84532":    "https://sepolia.basescan.org",
	"11155111": "https://sepolia.etherscan.io",
}

// toolInfo identifies this binary: the release version if set at build
// time, else the module version, and the VCS revision from the build info.
func toolInfo() Tool {
	t := Tool{Name: "verilog-verify", Version: version, Commit: "unknown"}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		if t.Version == "" {
			t.Version = "unknown"
		}
		return t
	}
	if t.Version == "" {
		t.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			t.Commit = s.Value
		case "vcs.modified":
			t.Modified = s.Value == "true"
		}
	}
	return t
}

type reportParams struct {
	agentID, chainID, registry, finality, blockHash, explorer string
	from, to, generatedAt                                     time.Time
	blockNumber                                               uint64
	allowIncomplete                                           bool
	tool                                                      Tool
}

// bundlePath is where epoch ep's bundle goes in the export.
func bundlePath(ep uint64) string { return fmt.Sprintf("evidence/epoch-%d.json", ep) }

func buildReport(a *verify.AuditReport, byRel map[string]bundleFile, loadWarnings []string, p reportParams) *Report {
	rep := &Report{
		Format:      reportFormat,
		GeneratedAt: p.generatedAt.Format(time.RFC3339),
		Tool:        p.tool,
		AgentID:     p.agentID,
		AgentKey:    a.AgentKey.Hex(),
		Window: Window{From: p.from.Format(time.RFC3339), To: p.to.Format(time.RFC3339),
			SelectedBy: "anchor block time of each epoch, read from the registry: from <= anchored_at < to"},
		Chain: Chain{ChainID: p.chainID, Registry: p.registry, Finality: p.finality,
			VerdictBlockNumber: p.blockNumber, VerdictBlockHash: p.blockHash, Explorer: p.explorer},
		AllowIncomplete: p.allowIncomplete,
		Epochs:          []EpochReport{},
		Runs:            []RunReport{},
		Warnings:        append(append([]string{}, loadWarnings...), a.Warnings...),
	}
	t := &rep.Totals
	for _, e := range a.Epochs {
		er := EpochReport{Epoch: e.EpochID, InWindow: e.InWindow, Root: e.Anchor.Root.Hex(), LogCount: e.Anchor.Count,
			AnchoredAt: e.Anchor.Time.Format(time.RFC3339), Problem: e.Problem}
		if e.Evidence != nil {
			b := byRel[e.Evidence.Source].bundle
			er.AnchorTx, er.AnchorBlock, er.Bundle = b.TxHash, b.BlockNumber, bundlePath(e.EpochID)
		}
		if e.Problem != "" {
			t.EvidenceProblems++
		}
		if e.InWindow {
			t.EpochsInWindow++
			t.EventsInWindow += int(e.Anchor.Count)
		}
		rep.Epochs = append(rep.Epochs, er)
	}
	t.Epochs = len(rep.Epochs)
	t.ContextEpochs = t.Epochs - t.EpochsInWindow
	for _, r := range a.Runs {
		rr := RunReport{RunID: r.RunID, Verdict: r.Verdict, Reason: r.Reason, Epochs: []uint64{}, Warnings: []string{}}
		if r.Report != nil {
			rr.Steps, rr.RunEndStatus, rr.SDKDropped = r.Report.LastStep, r.Report.EndStatus, r.Report.SDKDropped
			rr.Epochs = append(rr.Epochs, r.Report.Epochs...)
			rr.Warnings = append(rr.Warnings, r.Report.Warnings...)
		}
		switch r.Verdict {
		case verify.VerdictSuccess:
			t.Success++
		case verify.VerdictFailure:
			t.Failure++
		case verify.VerdictIncomplete:
			t.Incomplete++
		default:
			t.NotFinal++
		}
		rep.Runs = append(rep.Runs, rr)
	}
	t.Runs = len(rep.Runs)
	switch {
	case t.Failure > 0 || t.EvidenceProblems > 0:
		rep.Verdict = verify.VerdictFailure
	case t.Incomplete > 0 || t.NotFinal > 0:
		rep.Verdict = verify.VerdictIncomplete
	default:
		rep.Verdict = verify.VerdictSuccess
	}
	return rep
}

// renderExport returns every file of the export (path -> content) except
// the manifest.
func renderExport(rep *Report, a *verify.AuditReport, byRel map[string]bundleFile, rpc string) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, e := range a.Epochs {
		if e.Evidence != nil {
			files[bundlePath(e.EpochID)] = byRel[e.Evidence.Source].data
		}
	}
	j, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	files["report.json"] = append(j, '\n')
	files["report.md"] = []byte(reportMarkdown(rep))
	files["README.md"] = []byte(readmeMarkdown(rep, rpc))
	return files, nil
}

func (r *Report) link(kind, value string) string {
	if r.Chain.Explorer == "" || value == "" {
		return "`" + value + "`"
	}
	return fmt.Sprintf("[`%s`](%s/%s/%s)", value, r.Chain.Explorer, kind, value)
}

func reportMarkdown(r *Report) string {
	var b strings.Builder
	t := r.Totals
	fmt.Fprintf(&b, "# VeriLog audit report: %s\n\n", r.AgentID)
	fmt.Fprintf(&b, "**Verdict: %s.** %d runs with events in the window: %d SUCCESS, %d FAILURE, %d SUCCESS-INCOMPLETE, %d not final. "+
		"%d evidence problems.\n\n", r.Verdict, t.Runs, t.Success, t.Failure, t.Incomplete, t.NotFinal, t.EvidenceProblems)
	b.WriteString("| | |\n|---|---|\n")
	rows := [][2]string{
		{"Agent", fmt.Sprintf("`%s` (agent key `%s`)", r.AgentID, r.AgentKey)},
		{"Window (anchor time)", fmt.Sprintf("%s (inclusive) to %s (exclusive)", r.Window.From, r.Window.To)},
		{"Chain", fmt.Sprintf("chain id %s, registry %s", r.Chain.ChainID, r.link("address", r.Chain.Registry))},
		{"Verdict block", fmt.Sprintf("%d, hash `%s` (finality %s)", r.Chain.VerdictBlockNumber, r.Chain.VerdictBlockHash, r.Chain.Finality)},
		{"Tool", fmt.Sprintf("%s %s, commit `%s`%s", r.Tool.Name, r.Tool.Version, r.Tool.Commit, map[bool]string{true: " (modified)"}[r.Tool.Modified])},
		{"Generated", r.GeneratedAt},
		{"Missing run_end", map[bool]string{true: "SUCCESS-INCOMPLETE (--allow-incomplete)", false: "FAILURE"}[r.AllowIncomplete]},
	}
	for _, row := range rows {
		fmt.Fprintf(&b, "| %s | %s |\n", row[0], row[1])
	}
	fmt.Fprintf(&b, "\n## Epochs\n\n%d epochs exported: %d in the window, %d context (needed because run mode checks every epoch anchored for the agent). "+
		"%d events in the window. Root, count and anchor time are read from the registry at the verdict block; the transaction and block are as recorded in the bundle.\n\n",
		t.Epochs, t.EpochsInWindow, t.ContextEpochs, t.EventsInWindow)
	b.WriteString("| Epoch | In window | Root | Logs | Anchored at | Anchor tx | Block | Problem |\n|---|---|---|---|---|---|---|---|\n")
	for _, e := range r.Epochs {
		in := "context"
		if e.InWindow {
			in = "yes"
		}
		fmt.Fprintf(&b, "| %d | %s | `%s` | %d | %s | %s | %d | %s |\n", e.Epoch, in, e.Root, e.LogCount, e.AnchoredAt,
			r.link("tx", e.AnchorTx), e.AnchorBlock, mdCell(e.Problem))
	}
	b.WriteString("\n## Runs\n\n")
	if len(r.Runs) == 0 {
		b.WriteString("No runs have events in the window.\n")
	} else {
		b.WriteString("| Run | Verdict | Steps | run_end status | Epochs | SDK dropped | Reason |\n|---|---|---|---|---|---|---|\n")
		for _, run := range r.Runs {
			eps := make([]string, len(run.Epochs))
			for i, e := range run.Epochs {
				eps[i] = fmt.Sprint(e)
			}
			fmt.Fprintf(&b, "| `%s` | %s | %d | %s | %s | %d | %s |\n", run.RunID, run.Verdict, run.Steps, mdCell(run.RunEndStatus),
				strings.Join(eps, ", "), run.SDKDropped, mdCell(run.Reason))
		}
	}
	var warnings []string
	warnings = append(warnings, r.Warnings...)
	for _, run := range r.Runs {
		for _, w := range run.Warnings {
			warnings = append(warnings, fmt.Sprintf("run %s: %s", run.RunID, w))
		}
	}
	if len(warnings) > 0 {
		b.WriteString("\n## Warnings\n\n")
		for _, w := range warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	return b.String()
}

func mdCell(s string) string { return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s) }

func readmeMarkdown(r *Report, rpc string) string {
	var b strings.Builder
	flags := fmt.Sprintf("--agent-id %s --rpc %s --contract %s --chain-id %s --finality %s",
		shellQuote(r.AgentID), shellQuote(rpc), r.Chain.Registry, r.Chain.ChainID, r.Chain.Finality)
	exampleRun, exampleEpoch := "<run-id>", uint64(1)
	if len(r.Runs) > 0 {
		exampleRun = r.Runs[0].RunID
	}
	for _, e := range r.Epochs {
		if e.InWindow && e.Bundle != "" {
			exampleEpoch = e.Epoch
			break
		}
	}
	fmt.Fprintf(&b, `# VeriLog evidence: %s, %s to %s

This folder is the tamper-evident log of AI agent %s for the period above,
selected by the time each epoch was anchored on chain. The verdict is
**%s**; see report.md (report.json has the same data).

| File | Content |
|---|---|
| report.md, report.json | Per-epoch anchors and per-run verdicts, with totals |
| evidence/epoch-N.json | The daemon's evidence bundles, byte for byte: every event (signed canonical JSON), its Merkle proof, the root and the anchor transaction |
| MANIFEST.sha256 | SHA-256 of every other file (sha256sum format) |

## Registry

- Chain id %s, registry %s
- Verdict reached at block %d (%s), finality %s
- Explorer: %s

## What VeriLog proves, and what it does not

A run that verifies was signed event by event inside the agent with a key
registered on chain for it (and valid when its events were anchored), and
is complete from step 1 to its run_end: no event removed, inserted, altered
or anchored after its successor. Changing any byte of an anchored event
fails verification. The checks trust only the chain, never the host that
produced these files.

It does not prove that a whole run was not suppressed or delayed (nothing
is anchored for it), cannot tell a truncated run from a crashed agent (both
lack run_end), cannot tell the order of events within one epoch, does not
prove that a payload is true, and does not protect against a stolen agent
key. Event timestamps are the agent's claim; the anchor time is an upper
bound. The full list: docs/security.md in the VeriLog repository.

## Re-verify independently

Build verilog-verify from the VeriLog repository at commit %s (go build
./cmd/verilog-verify in daemon/), and use any RPC endpoint for chain %s.

`+"```"+`sh
# 1. Integrity of this folder (exit 0: unchanged; 1: a file changed).
verilog-verify audit-check .

# 2. Any run (run ids in report.md); exit 0 SUCCESS, 1 FAILURE.
verilog-verify --run-id %s --bundles evidence %s

# 3. Any single event: export it with its proof, then verify it.
verilog-verify export --bundle evidence/epoch-%d.json --index 0 --out ev
verilog-verify --event ev/event.json --proof ev/proof.json --epoch %d %s

# 4. The whole report again.
verilog-verify audit-export --bundles evidence --from %s --to %s %s --out re-export
`+"```"+`

MANIFEST.sha256 only shows that the folder is unchanged since it was
written; record its own SHA-256 in your workpapers. Steps 2 to 4 check the
evidence against the chain itself.

Run mode needs a bundle for every epoch anchored for the agent up to the
latest final one (%d when this was written). If the agent has anchored
epochs since, add their bundles (from a newer export) to evidence/ before
re-verifying runs, or run mode reports the evidence as incomplete. Single
events (step 3) verify with no other bundles.
`, r.AgentID, r.Window.From, r.Window.To, shellQuote(r.AgentID), r.Verdict,
		r.Chain.ChainID, r.link("address", r.Chain.Registry), r.Chain.VerdictBlockNumber, r.Chain.VerdictBlockHash, r.Chain.Finality,
		orNone(r.Chain.Explorer), r.Tool.Commit, r.Chain.ChainID,
		shellQuote(exampleRun), flags, exampleEpoch, exampleEpoch, flags,
		r.Window.From, r.Window.To, flags, r.Totals.Epochs)
	return b.String()
}

func orNone(s string) string {
	if s == "" {
		return "none configured"
	}
	return s
}

// shellQuote quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@+,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeExport writes files and their manifest into a temporary directory
// next to out, then renames it to out, so a failed export leaves nothing.
// It returns the manifest's own SHA-256.
func writeExport(out string, files map[string][]byte) (string, error) {
	parent := filepath.Dir(filepath.Clean(out))
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(out)+".tmp-")
	if err != nil {
		return "", fmt.Errorf("--out: %w", err)
	}
	done := false
	defer func() {
		if !done {
			os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		dst := filepath.Join(tmp, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(dst, files[p], 0o644); err != nil {
			return "", err
		}
	}
	manifest := buildManifest(files)
	if err := os.WriteFile(filepath.Join(tmp, manifestName), manifest, 0o644); err != nil {
		return "", err
	}
	if _, err := os.Lstat(out); err == nil {
		return "", fmt.Errorf("--out %s already exists", out)
	}
	if err := os.Rename(tmp, out); err != nil {
		return "", fmt.Errorf("--out: %w", err)
	}
	done = true
	return sha256Hex(manifest), nil
}
