package guestagent

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openPTY(rows, cols uint16) (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = master.Close()
		}
	}()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("unlock PTY: %w", err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect PTY number: %w", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open PTY slave: %w", err)
	}
	if err := resizePTY(master, rows, cols); err != nil {
		_ = slave.Close()
		return nil, nil, err
	}
	cleanup = false
	return master, slave, nil
}

func resizePTY(master *os.File, rows, cols uint16) error {
	if master == nil || rows == 0 || cols == 0 {
		return fmt.Errorf("valid PTY and nonzero dimensions are required")
	}
	return unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
}
