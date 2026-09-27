// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package guardianwatch is the enterprise hook guardian's filesystem
// watcher: it reports fsnotify events for watched directories and for the
// files in them that the guardian acts on.
//
// A root guardian watches directories in users' homes. On macOS fsnotify
// uses kqueue, which opens every entry of a watched directory with the
// caller's credentials, following symbolic links and waiting on named
// pipes, so a user could hold up the guardian (and every other user's
// repairs) with a link to a FIFO. The macOS watcher here opens only the
// watched directories and the named files in them, for change notification
// only, never follows a final symbolic link and never waits. Other
// platforms use fsnotify, whose inotify and ReadDirectoryChangesW backends
// do not open directory entries.
package guardianwatch

import "github.com/fsnotify/fsnotify"

// Watcher is the part of fsnotify.Watcher the guardian uses, plus SetFiles.
type Watcher interface {
	// Add watches dir, a directory that is not a symbolic link.
	Add(dir string) error
	// Remove stops watching dir.
	Remove(dir string) error
	// SetFiles names the files, by absolute path, whose changes the
	// guardian acts on. Changes to them are reported while their directory
	// is watched. A watcher may also report other entries of watched
	// directories (fsnotify does); the guardian ignores those.
	SetFiles(paths []string)
	// Events and Errors are closed by Close.
	Events() <-chan fsnotify.Event
	Errors() <-chan error
	Close() error
}

// New returns the watcher for this platform.
func New() (Watcher, error) {
	return newPlatformWatcher()
}
