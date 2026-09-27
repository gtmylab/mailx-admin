//go:build !unix

package logs

import "os"

// fileIdentity is the non-unix fallback. There is no inode to compare, so
// rotation is detected by the ingester's size check alone.
func fileIdentity(path string) (inode int64, size int64, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	return 0, fi.Size(), nil
}
