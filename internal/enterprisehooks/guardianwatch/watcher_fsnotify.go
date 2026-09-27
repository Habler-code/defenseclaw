//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianwatch

import "github.com/fsnotify/fsnotify"

// fsnotifyWatcher reports every entry of the watched directories; SetFiles
// has nothing to do.
type fsnotifyWatcher struct {
	watcher *fsnotify.Watcher
}

func newPlatformWatcher() (Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &fsnotifyWatcher{watcher: watcher}, nil
}

func (w *fsnotifyWatcher) Add(dir string) error          { return w.watcher.Add(dir) }
func (w *fsnotifyWatcher) Remove(dir string) error       { return w.watcher.Remove(dir) }
func (w *fsnotifyWatcher) SetFiles([]string)             {}
func (w *fsnotifyWatcher) Events() <-chan fsnotify.Event { return w.watcher.Events }
func (w *fsnotifyWatcher) Errors() <-chan error          { return w.watcher.Errors }
func (w *fsnotifyWatcher) Close() error                  { return w.watcher.Close() }
