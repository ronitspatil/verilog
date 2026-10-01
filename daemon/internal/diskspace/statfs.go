//go:build linux || darwin || freebsd

package diskspace

import "syscall"

func free0(path string) (uint64, uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) // int64 on linux, uint32 on darwin
	return uint64(st.Bavail) * bs, uint64(st.Blocks) * bs, nil
}
