package vm

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// CloneFile makes dst a private copy of src: a reflink (instant, copy-on-write) where the
// filesystem supports it, such as btrfs or XFS, otherwise a full copy.
func CloneFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := unix.IoctlFileClone(int(out.Fd()), int(in.Fd())); err == nil {
		return out.Close()
	} else if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EXDEV) && !errors.Is(err, unix.EINVAL) {
		out.Close()
		os.Remove(dst)
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
