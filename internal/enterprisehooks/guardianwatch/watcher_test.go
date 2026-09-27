//go:build darwin || linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianwatch

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

const eventWait = 5 * time.Second

func newTestWatcher(t *testing.T) Watcher {
	t.Helper()
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// requireEvent waits for an event on path that includes op, skipping
// others.
func requireEvent(t *testing.T, w Watcher, path string, op fsnotify.Op) {
	t.Helper()
	deadline := time.After(eventWait)
	for {
		select {
		case event, ok := <-w.Events():
			if !ok {
				t.Fatalf("event channel closed while waiting for %s on %s", op, path)
			}
			if filepath.Clean(event.Name) == path && event.Op&op != 0 {
				return
			}
		case err := <-w.Errors():
			t.Fatalf("watcher error while waiting for %s on %s: %v", op, path, err)
		case <-deadline:
			t.Fatalf("no %s event on %s within %s", op, path, eventWait)
		}
	}
}

// requireNoEvent fails on any event on path within a short window.
func requireNoEvent(t *testing.T, w Watcher, path string) {
	t.Helper()
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case event, ok := <-w.Events():
			if !ok {
				return
			}
			if filepath.Clean(event.Name) == path {
				t.Fatalf("unexpected event %s", event)
			}
		case <-deadline:
			return
		}
	}
}

func TestWatcherReportsChangesToNamedFiles(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "hook.sh")
	config := filepath.Join(dir, "config.toml")
	writeTestFile(t, hook, "#!/bin/sh\n")
	writeTestFile(t, config, "model = \"a\"\n")
	w := newTestWatcher(t)
	w.SetFiles([]string{hook, config})
	if err := w.Add(dir); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(hook, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("exit 0\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	requireEvent(t, w, hook, fsnotify.Write)

	if err := os.Chmod(hook, 0o700); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, hook, fsnotify.Chmod)

	// An atomic replacement of the file.
	temp := filepath.Join(dir, "config.toml.tmp")
	writeTestFile(t, temp, "model = \"b\"\n")
	if err := os.Rename(temp, config); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, config, fsnotify.Create)
	// The replacement is watched in its turn.
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, config, fsnotify.Chmod)

	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, hook, fsnotify.Remove)
	writeTestFile(t, hook, "#!/bin/sh\n")
	requireEvent(t, w, hook, fsnotify.Create)
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, hook, fsnotify.Chmod)

	if err := w.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hook, 0o700); err != nil {
		t.Fatal(err)
	}
	requireNoEvent(t, w, hook)
}

// A named file becomes watched when SetFiles names it after its directory
// was added.
func TestWatcherPicksUpFilesNamedAfterAdd(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "hook.sh")
	writeTestFile(t, hook, "#!/bin/sh\n")
	w := newTestWatcher(t)
	if err := w.Add(dir); err != nil {
		t.Fatal(err)
	}
	w.SetFiles([]string{hook})
	if err := os.Chmod(hook, 0o700); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, hook, fsnotify.Chmod)
}

// A user can put a symbolic link to a named pipe into a watched directory,
// under a watched name or any other. Neither adding the directory nor
// reading its later events may wait on the pipe.
func TestWatcherIsNotHeldUpByALinkToANamedPipe(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Release anything still waiting to open the pipe.
		if writer, err := os.OpenFile(pipe, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = writer.Close()
		}
	})
	config := filepath.Join(dir, "config.toml")
	hook := filepath.Join(dir, "hook.sh")
	for _, link := range []string{config, filepath.Join(dir, "other")} {
		if err := os.Symlink(pipe, link); err != nil {
			t.Fatal(err)
		}
	}
	w := newTestWatcher(t)
	w.SetFiles([]string{config, hook})
	added := make(chan error, 1)
	go func() { added <- w.Add(dir) }()
	select {
	case err := <-added:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(eventWait):
		t.Fatal("Add waited on a named pipe behind a symbolic link")
	}

	// Links created after Add, then an ordinary change: the reader must
	// still be running.
	if err := os.Symlink(pipe, filepath.Join(dir, "later")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(pipe, hook); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, hook, fsnotify.Create)
	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, hook, fsnotify.Remove)
	writeTestFile(t, hook, "#!/bin/sh\n")
	requireEvent(t, w, hook, fsnotify.Create)
}

func TestWatcherCloseClosesItsChannels(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Add(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-w.Events():
		if ok {
			t.Fatal("event after Close")
		}
	case <-time.After(eventWait):
		t.Fatal("Close left the event channel open")
	}
	if err := w.Add(t.TempDir()); err == nil {
		t.Fatal("Add after Close succeeded")
	}
}
