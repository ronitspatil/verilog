//go:build !unix

package main

import "os"

// lockDataDir is a no-op where flock is unavailable; run one daemon per data dir.
func lockDataDir(string) (*os.File, error) { return nil, nil }
