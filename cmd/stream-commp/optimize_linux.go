package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func init() {
	ioOptimizations = append(ioOptimizations, func(st os.FileInfo, fh *os.File) error {

		// pipe
		if st.Mode()&os.ModeNamedPipe != 0 {

			// Raise the size of the passed-in pipe. Do so blindly without err checks,
			// trying smaller and smaller powers of 2 ( starting from 32MiB ), due to
			// the entire process being opportunistic and dependent on system tuning.
			// This unfortunately only works on Linux.
			// Capped by /proc/sys/fs/pipe-max-size
			// Background: https://github.com/afborchert/pipebuf#related-discussions
			for pipeSize := 32 << 20; pipeSize > 512; pipeSize /= 2 {
				if _, err := unix.FcntlInt(fh.Fd(), unix.F_SETPIPE_SZ, pipeSize); err == nil {
					return nil
				}
			}
		}

		return nil
	})
}
