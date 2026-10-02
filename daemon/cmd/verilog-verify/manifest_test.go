package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSample(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "export")
	files := map[string][]byte{
		"README.md":             []byte("readme\n"),
		"report.json":           []byte("{}\n"),
		"evidence/epoch-1.json": []byte(`{"epoch_id":1}`),
		"evidence/epoch-2.json": []byte(`{"epoch_id":2}`),
	}
	sum, err := writeExport(out, files)
	if err != nil {
		t.Fatal(err)
	}
	m, err := os.ReadFile(filepath.Join(out, manifestName))
	if err != nil || sha256Hex(m) != sum {
		t.Fatalf("manifest sum: %v", err)
	}
	want := sha256Hex(files["README.md"]) + "  README.md\n" +
		sha256Hex(files["evidence/epoch-1.json"]) + "  evidence/epoch-1.json\n" +
		sha256Hex(files["evidence/epoch-2.json"]) + "  evidence/epoch-2.json\n" +
		sha256Hex(files["report.json"]) + "  report.json\n"
	if string(m) != want {
		t.Fatalf("manifest:\n%s\nwant:\n%s", m, want)
	}
	return out
}

func auditCheck(dir string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"audit-check", dir}, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestAuditCheck(t *testing.T) {
	dir := writeSample(t)
	if code, out, _ := auditCheck(dir); code != exitVerified || out != "[OK] All 4 files match MANIFEST.sha256\n" {
		t.Fatalf("clean: %d %q", code, out)
	}

	// One changed byte.
	p := filepath.Join(dir, "evidence/epoch-2.json")
	data, _ := os.ReadFile(p)
	data[3] ^= 1
	os.WriteFile(p, data, 0o644)
	code, out, errOut := auditCheck(dir)
	if code != exitTampered || !strings.HasPrefix(out, "[CHANGED]") || errOut != "changed: evidence/epoch-2.json\n" {
		t.Fatalf("changed: %d %q %q", code, out, errOut)
	}

	// A missing file and an added one.
	os.Remove(filepath.Join(dir, "README.md"))
	os.WriteFile(filepath.Join(dir, "evidence/epoch-3.json"), []byte("{}"), 0o644)
	code, _, errOut = auditCheck(dir)
	if code != exitTampered || errOut != "changed: evidence/epoch-2.json\nmissing: README.md\nunlisted file: evidence/epoch-3.json\n" {
		t.Fatalf("missing/added: %d %q", code, errOut)
	}
}

func TestAuditCheckOperationalErrors(t *testing.T) {
	if code, _, errOut := auditCheck(t.TempDir()); code != exitOperational || !strings.Contains(errOut, "not an audit export") {
		t.Fatalf("no manifest: %d %q", code, errOut)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"audit-check"}, &stdout, &stderr); code != exitOperational || stdout.Len() != 0 {
		t.Fatalf("no dir: %d", code)
	}
	for _, bad := range []string{
		"", "nothex  a\n", strings.Repeat("0", 64) + "  ../escape\n", strings.Repeat("0", 64) + "  /abs\n",
		strings.Repeat("0", 64) + "  a\n" + strings.Repeat("1", 64) + "  a\n", strings.Repeat("0", 64) + " a\n",
	} {
		if _, err := parseManifest([]byte(bad)); err == nil {
			t.Errorf("accepted manifest %q", bad)
		}
	}
}

// A failed write leaves no folder behind, and an existing --out is never
// replaced.
func TestWriteExportIsAllOrNothing(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "export")
	os.Mkdir(out, 0o755)
	if _, err := writeExport(out, map[string][]byte{"a": []byte("x")}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing out: %v", err)
	}
	// A path that cannot be created (a file where a directory must go).
	if _, err := writeExport(filepath.Join(parent, "bad"), map[string][]byte{"a": []byte("x"), "a/b": []byte("y")}); err == nil {
		t.Fatal("no error")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 || entries[0].Name() != "export" {
		t.Fatalf("left behind: %v", entries)
	}
}
