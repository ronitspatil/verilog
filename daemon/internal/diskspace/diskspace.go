// Package diskspace reports the free space of a file system.
package diskspace

import "errors"

// ErrUnsupported is returned where free space cannot be read.
var ErrUnsupported = errors.New("diskspace: not supported on this platform")

// Free returns the bytes available to unprivileged users and the total size
// of the file system holding path.
func Free(path string) (free, total uint64, err error) { return free0(path) }
