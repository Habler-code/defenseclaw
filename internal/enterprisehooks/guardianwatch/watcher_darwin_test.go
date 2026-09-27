//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianwatch

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
)

func openDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// The guardian opens a watched directory and its named regular files, not
// the directory's other entries (fsnotify's kqueue backend opens them all).
func TestWatcherOpensOnlyTheDirectoryAndNamedFiles(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, "hook.sh")
	writeTestFile(t, hook, "#!/bin/sh\n")
	for i := 0; i < 200; i++ {
		writeTestFile(t, filepath.Join(dir, fmt.Sprintf("session-%03d.jsonl", i)), "{}\n")
	}
	if err := os.Symlink(hook, filepath.Join(dir, "config.toml")); err != nil {
		t.Fatal(err)
	}
	w := newTestWatcher(t)
	w.SetFiles([]string{hook, filepath.Join(dir, "config.toml"), filepath.Join(dir, "missing")})
	before := openDescriptorCount(t)
	if err := w.Add(dir); err != nil {
		t.Fatal(err)
	}
	// The directory and hook.sh; the named link and missing entry are not
	// opened.
	if opened := openDescriptorCount(t) - before; opened != 2 {
		t.Fatalf("Add opened %d descriptors, want 2", opened)
	}
	if err := w.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if left := openDescriptorCount(t) - before; left != 0 {
		t.Fatalf("Remove left %d descriptors open", left)
	}
}

// A watched directory that is replaced by a symbolic link is not followed.
func TestWatcherRefusesALinkedDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	w := newTestWatcher(t)
	if err := w.Add(link); err == nil {
		t.Fatal("Add followed a symbolic link to a directory")
	}
}

// Moving a watched directory away ends its watch, as with fsnotify.
func TestWatcherDropsARenamedDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "watched")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(dir, "hook.sh")
	writeTestFile(t, hook, "#!/bin/sh\n")
	w := newTestWatcher(t)
	w.SetFiles([]string{hook})
	if err := w.Add(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+".moved"); err != nil {
		t.Fatal(err)
	}
	requireEvent(t, w, dir, fsnotify.Rename)
	if err := w.Remove(dir); err == nil {
		t.Fatal("renamed directory is still watched")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := w.Add(dir); err != nil {
		t.Fatalf("add the new directory: %v", err)
	}
	writeTestFile(t, hook, "#!/bin/sh\n")
	requireEvent(t, w, hook, fsnotify.Create)
}
