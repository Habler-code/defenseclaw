// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openStateFileReadOnlyNonblocking opens path without waiting for a FIFO
// writer or a device, so the caller can reject anything but a regular file
// instead of blocking in open(2).
func openStateFileReadOnlyNonblocking(path string) (*os.File, error) {
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
}
