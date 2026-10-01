package diskspace

import "testing"

func TestFree(t *testing.T) {
	free, total, err := Free(t.TempDir())
	if err == ErrUnsupported {
		t.Skip(err)
	}
	if err != nil || total == 0 || free > total {
		t.Fatalf("Free = %d, %d, %v", free, total, err)
	}
}
