package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// manifestName is the export's manifest: "<sha256 hex>  <path>" per file,
// sorted by path (the format of sha256sum, so `sha256sum -c` also checks it).
const manifestName = "MANIFEST.sha256"

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// buildManifest lists every file (path -> content), sorted by path.
func buildManifest(files map[string][]byte) []byte {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var b bytes.Buffer
	for _, p := range paths {
		fmt.Fprintf(&b, "%s  %s\n", sha256Hex(files[p]), p)
	}
	return b.Bytes()
}

// parseManifest reads a manifest; paths must be relative, clean and unique.
func parseManifest(data []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		sum, p, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || p == "" {
			return nil, fmt.Errorf("%s line %d: not \"<sha256>  <path>\"", manifestName, n)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("%s line %d: bad hash", manifestName, n)
		}
		if path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") || p == manifestName {
			return nil, fmt.Errorf("%s line %d: bad path %q", manifestName, n, p)
		}
		if _, dup := out[p]; dup {
			return nil, fmt.Errorf("%s line %d: %q listed twice", manifestName, n, p)
		}
		out[p] = strings.ToLower(sum)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is empty", manifestName)
	}
	return out, nil
}

// checkManifest re-hashes the files of dir against its manifest and returns
// the problems: changed, missing and unlisted files, sorted.
func checkManifest(dir string) (problems []string, files int, err error) {
	data, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return nil, 0, err
	}
	want, err := parseManifest(data)
	if err != nil {
		return nil, 0, err
	}
	found := map[string]bool{}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == manifestName {
			return nil
		}
		found[rel] = true
		sum, listed := want[rel]
		if !listed {
			problems = append(problems, "unlisted file: "+rel)
			return nil
		}
		if !d.Type().IsRegular() {
			problems = append(problems, "not a regular file: "+rel)
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != sum {
			problems = append(problems, "changed: "+rel)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	for p := range want {
		if !found[p] {
			problems = append(problems, "missing: "+p)
		}
	}
	sort.Strings(problems)
	return problems, len(want), nil
}

// runAuditCheck checks an export folder against its manifest: exit 0 when
// every file matches, 1 when any changed, is missing or was added, 2 when
// the folder or manifest cannot be read.
func runAuditCheck(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: verilog-verify audit-check <export dir>")
		return exitOperational
	}
	problems, n, err := checkManifest(args[0])
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = fmt.Errorf("%s: no %s (not an audit export?)", args[0], manifestName)
		}
		fmt.Fprintln(stderr, "error:", err)
		return exitOperational
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(stderr, p)
		}
		fmt.Fprintf(stdout, "[CHANGED] Export Does Not Match %s (%d problems)\n", manifestName, len(problems))
		return exitTampered
	}
	fmt.Fprintf(stdout, "[OK] All %d files match %s\n", n, manifestName)
	return exitVerified
}
