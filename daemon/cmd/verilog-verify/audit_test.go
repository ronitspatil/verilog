package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ronitspatil/verilog/daemon/internal/canonical"
	"github.com/ronitspatil/verilog/daemon/internal/store"
	"github.com/ronitspatil/verilog/daemon/internal/verify"
)

// sampleAudit is an audit of two epochs (the second in the window) and the
// given run verdicts.
func sampleAudit(verdicts ...string) (*verify.AuditReport, map[string]bundleFile) {
	byRel := map[string]bundleFile{}
	a := &verify.AuditReport{AgentKey: canonical.AgentKey("agent-1"), LatestEpoch: 2}
	for ep := uint64(1); ep <= 2; ep++ {
		rel := "sub/epoch-" + string(rune('0'+ep)) + ".json"
		byRel[rel] = bundleFile{rel: rel, data: []byte(`{"epoch_id":` + string(rune('0'+ep)) + "}\n"),
			bundle: store.Bundle{EpochID: ep, TxHash: "0xtx" + string(rune('0'+ep)), BlockNumber: 100 + ep}}
		a.Epochs = append(a.Epochs, verify.AuditEpoch{EpochID: ep, InWindow: ep == 2,
			Anchor:   verify.Anchor{Count: 3, Time: time.Unix(1_800_000_000+int64(ep), 0).UTC(), Found: true},
			Evidence: &verify.EpochEvidence{Source: rel, EpochID: ep}})
	}
	for i, v := range verdicts {
		r := verify.AuditRun{RunID: "run-" + string(rune('a'+i)), Verdict: v}
		if v != verify.VerdictNotFinal {
			r.Report = &verify.RunReport{LastStep: 3, EndStatus: "ok", Epochs: []uint64{2}, Verified: v != verify.VerdictFailure}
		}
		if v == verify.VerdictFailure {
			r.Reason = "fork | at step 2"
		}
		a.Runs = append(a.Runs, r)
	}
	return a, byRel
}

func sampleParams() reportParams {
	return reportParams{agentID: "agent-1", chainID: "84532", registry: "0xd4735aA9414E249B2367bfB5D141A76993a5dD4C",
		finality: "finalized", blockHash: "0xblock", blockNumber: 7, explorer: "https://sepolia.basescan.org",
		from: time.Unix(1_800_000_001, 0).UTC(), to: time.Unix(1_800_000_100, 0).UTC(),
		generatedAt: time.Unix(1_900_000_000, 0).UTC(), tool: Tool{Name: "verilog-verify", Version: "v1", Commit: "abc"}}
}

func TestBuildReportVerdictsAndExitCodes(t *testing.T) {
	S, F, I, N := verify.VerdictSuccess, verify.VerdictFailure, verify.VerdictIncomplete, verify.VerdictNotFinal
	for _, tc := range []struct {
		runs    []string
		problem bool
		verdict string
		exit    int
	}{
		{nil, false, S, exitVerified},
		{[]string{S, S}, false, S, exitVerified},
		{[]string{S, I}, false, I, exitIncomplete},
		{[]string{S, N}, false, I, exitIncomplete},
		{[]string{I, F, N}, false, F, exitTampered},
		{[]string{S}, true, F, exitTampered},
	} {
		a, byRel := sampleAudit(tc.runs...)
		if tc.problem {
			a.Epochs[0].Problem = "no evidence bundle for this epoch"
		}
		rep := buildReport(a, byRel, nil, sampleParams())
		if rep.Verdict != tc.verdict || rep.exitCode() != tc.exit || rep.Totals.Runs != len(tc.runs) {
			t.Errorf("%v problem=%v: verdict %s exit %d, want %s %d", tc.runs, tc.problem, rep.Verdict, rep.exitCode(), tc.verdict, tc.exit)
		}
	}

	a, byRel := sampleAudit(S, F, I, N)
	rep := buildReport(a, byRel, []string{"ignored x"}, sampleParams())
	want := Totals{Epochs: 2, EpochsInWindow: 1, ContextEpochs: 1, EventsInWindow: 3, Runs: 4, Success: 1, Failure: 1, Incomplete: 1, NotFinal: 1}
	if rep.Totals != want {
		t.Fatalf("totals %+v, want %+v", rep.Totals, want)
	}
	e := rep.Epochs[1]
	if e.Epoch != 2 || !e.InWindow || e.AnchorTx != "0xtx2" || e.AnchorBlock != 102 || e.Bundle != "evidence/epoch-2.json" ||
		e.AnchoredAt != "2027-01-15T08:00:02Z" {
		t.Fatalf("%+v", e)
	}
	if r := rep.Runs[1]; r.Verdict != F || r.Reason == "" || r.Steps != 3 || rep.Runs[3].Steps != 0 || rep.Runs[3].Epochs == nil {
		t.Fatalf("%+v", rep.Runs)
	}
}

// The export is deterministic apart from generated_at, and carries the
// bundles byte for byte under evidence/.
func TestRenderExportDeterministic(t *testing.T) {
	render := func(at time.Time) map[string][]byte {
		a, byRel := sampleAudit(verify.VerdictSuccess, verify.VerdictFailure)
		p := sampleParams()
		p.generatedAt = at
		files, err := renderExport(buildReport(a, byRel, nil, p), a, byRel, "https://rpc.example")
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	f1, f2 := render(time.Unix(1, 0)), render(time.Unix(2, 0))
	if len(f1) != 5 || string(f1["evidence/epoch-2.json"]) != `{"epoch_id":2}`+"\n" {
		t.Fatalf("files: %v", keys(f1))
	}
	for p := range f1 {
		a := strings.ReplaceAll(string(f1[p]), "1970-01-01T00:00:01Z", "T")
		b := strings.ReplaceAll(string(f2[p]), "1970-01-01T00:00:02Z", "T")
		if a != b {
			t.Errorf("%s differs beyond the timestamp", p)
		}
	}
	md := string(f1["report.md"])
	for _, want := range []string{"**Verdict: FAILURE.**", "| 2 | yes |", "| 1 | context |", `fork \| at step 2`,
		"[`0xtx2`](https://sepolia.basescan.org/tx/0xtx2)"} {
		if !strings.Contains(md, want) {
			t.Errorf("report.md lacks %q", want)
		}
	}
	readme := string(f1["README.md"])
	for _, want := range []string{"verilog-verify audit-check .", "--run-id run-a --bundles evidence --agent-id agent-1 --rpc https://rpc.example",
		"--chain-id 84532", "export --bundle evidence/epoch-2.json", "docs/security.md"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md lacks %q", want)
		}
	}
	if !strings.Contains(string(f1["report.json"]), `"selected_by": "anchor block time of each epoch, read from the registry: from <= anchored_at < to"`) {
		t.Error("report.json escapes or lacks selected_by")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestParseWindowTime(t *testing.T) {
	for in, want := range map[string]string{
		"2026-04-01":                "2026-04-01T00:00:00Z",
		"2026-04-01T12:30:00+02:00": "2026-04-01T10:30:00Z",
	} {
		if got, err := parseWindowTime(in); err != nil || got.Format(time.RFC3339) != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if _, err := parseWindowTime("April 1"); err == nil {
		t.Error("accepted a free-form date")
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"agent-1": "agent-1", "team/bot 1": "'team/bot 1'", "it's": `'it'\''s'`, "": "''"} {
		if got := shellQuote(in); got != want {
			t.Errorf("%q: %s", in, got)
		}
	}
}

// Operational errors (exit 2) write nothing and print no verdict.
func TestAuditExportOperationalErrors(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	base := []string{"audit-export", "--agent-id", "a", "--bundles", dir, "--rpc", "http://127.0.0.1:1",
		"--contract", "0x5FbDB2315678afecb367f032d93F642f64180aa3", "--chain-id", "1"}
	out := filepath.Join(dir, "out")
	for _, tc := range []struct {
		extra []string
		want  string
	}{
		{[]string{"--from", "2026-01-01", "--to", "2026-02-01"}, "are required"},
		{[]string{"--from", "2026-01-01", "--to", "2026-02-01", "--out", existing}, "already exists"},
		{[]string{"--from", "2026-02-01", "--to", "2026-01-01", "--out", out}, "--from must be before --to"},
		{[]string{"--from", "yesterday", "--to", "2026-01-01", "--out", out}, "--from"},
		{[]string{"--from", "2026-01-01", "--to", "2026-02-01", "--out", out}, "eth_chainId"},
	} {
		var stdout, stderr bytes.Buffer
		args := append(append([]string{}, base...), tc.extra...)
		code := run(args, &stdout, &stderr)
		if code != exitOperational || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: exit %d stdout %q stderr %q", tc.extra, code, stdout.String(), stderr.String())
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%v: left %s behind", tc.extra, out)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}
