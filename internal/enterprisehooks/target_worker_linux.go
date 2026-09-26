//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func targetWorkerSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
}

// defaultTargetWorkerExecutable re-executes the exact image this process is
// running. /proc/self/exe is resolved by the kernel in the forked child, so
// replacing the installed binary path cannot substitute another program.
func defaultTargetWorkerExecutable() (string, string, error) {
	argv0, err := os.Executable()
	if err != nil || strings.TrimSpace(argv0) == "" {
		argv0 = "defenseclaw"
	}
	return "/proc/self/exe", argv0, nil
}

// hardenTargetWorkerProcess keeps other processes of the target user from
// inspecting or controlling the worker and ties its lifetime to the guardian.
func hardenTargetWorkerProcess(parentPID int) error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("mark process non-dumpable: %w", err)
	}
	// Changing credentials clears the parent-death signal; arm it again.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0); err != nil {
		return fmt.Errorf("arm parent-death signal: %w", err)
	}
	if os.Getppid() != parentPID {
		return errors.New("guardian exited before the worker started")
	}
	tracer, err := linuxTracerPID()
	if err != nil {
		return err
	}
	if tracer != 0 {
		return fmt.Errorf("process is traced by pid %d", tracer)
	}
	return nil
}

func linuxTracerPID() (int, error) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("inspect process tracer: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		value, ok := strings.CutPrefix(scanner.Text(), "TracerPid:")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, fmt.Errorf("parse process tracer: %w", err)
		}
		return pid, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("inspect process tracer: %w", err)
	}
	return 0, errors.New("inspect process tracer: TracerPid is missing")
}

func verifySavedTargetIDs(uid, gid int) error {
	ruid, euid, suid := unix.Getresuid()
	if ruid != uid || euid != uid || suid != uid {
		return fmt.Errorf("process uids are %d/%d/%d, want %d", ruid, euid, suid, uid)
	}
	rgid, egid, sgid := unix.Getresgid()
	if rgid != gid || egid != gid || sgid != gid {
		return fmt.Errorf("process gids are %d/%d/%d, want %d", rgid, egid, sgid, gid)
	}
	return nil
}
