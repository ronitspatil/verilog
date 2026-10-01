//go:build !(linux || darwin || freebsd)

package diskspace

func free0(string) (uint64, uint64, error) { return 0, 0, ErrUnsupported }
