//go:build unix

package logs

import "syscall"

// fileIdentity returns the inode and size of path so the ingester can detect
// log rotation. On unix-like systems the inode changes when logrotate swaps
// the file, which is more reliable than watching the size alone.
func fileIdentity(path string) (inode int64, size int64, err error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Ino), st.Size, nil
}
