//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianwatch

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/unix"
)

// openFlags opens a watched directory or file for change notification only
// (O_EVTONLY), opens a final symbolic link itself instead of its target
// (O_SYMLINK) and never waits (O_NONBLOCK), so no entry a user controls can
// hold up the guardian or make it open something else.
const openFlags = unix.O_EVTONLY | unix.O_NONBLOCK | unix.O_SYMLINK | unix.O_CLOEXEC

const noteFlags = unix.NOTE_DELETE | unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_ATTRIB |
	unix.NOTE_RENAME | unix.NOTE_REVOKE

// kqueueWatcher watches directories and the named files in them. A
// directory change (an entry added, removed or renamed) makes it look up
// the named files in that directory with fstatat, relative to the watched
// directory, without following links; it keeps a notification-only
// descriptor on each named file that is a regular file, for writes and
// attribute changes. No other entry is opened.
type kqueueWatcher struct {
	kq     int
	wake   [2]int
	events chan fsnotify.Event
	errors chan error
	done   chan struct{}
	exited chan struct{}
	once   sync.Once

	mu     sync.Mutex
	closed bool
	dirs   map[string]*watchedDir
	byFD   map[int]watchRef
	// files maps a directory to the names in it the guardian acts on.
	files map[string]map[string]struct{}
}

type watchedDir struct {
	path  string
	fd    int
	files map[string]*watchedFile
}

// watchedFile is the last seen state of one named entry.
type watchedFile struct {
	name   string
	fd     int // notification descriptor while the entry is a regular file, else -1
	exists bool
	dev    int32
	ino    uint64
	kind   uint16 // S_IFMT bits
}

type watchRef struct {
	dir  *watchedDir
	file *watchedFile // nil for the directory itself
}

func newPlatformWatcher() (Watcher, error) {
	syscall.ForkLock.RLock()
	kq, err := unix.Kqueue()
	if err == nil {
		unix.CloseOnExec(kq)
	}
	var wake [2]int
	pipeErr := error(nil)
	if err == nil {
		if pipeErr = unix.Pipe(wake[:]); pipeErr == nil {
			unix.CloseOnExec(wake[0])
			unix.CloseOnExec(wake[1])
		}
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("guardianwatch: kqueue: %w", err)
	}
	if pipeErr != nil {
		_ = unix.Close(kq)
		return nil, fmt.Errorf("guardianwatch: wake pipe: %w", pipeErr)
	}
	w := &kqueueWatcher{
		kq:     kq,
		wake:   wake,
		events: make(chan fsnotify.Event),
		errors: make(chan error),
		done:   make(chan struct{}),
		exited: make(chan struct{}),
		dirs:   map[string]*watchedDir{},
		byFD:   map[int]watchRef{},
		files:  map[string]map[string]struct{}{},
	}
	var change [1]unix.Kevent_t
	unix.SetKevent(&change[0], wake[0], unix.EVFILT_READ, unix.EV_ADD|unix.EV_ENABLE)
	if err := w.kevent(change[:]); err != nil {
		_ = unix.Close(kq)
		_ = unix.Close(wake[0])
		_ = unix.Close(wake[1])
		return nil, fmt.Errorf("guardianwatch: register wake pipe: %w", err)
	}
	go w.readEvents()
	return w, nil
}

func (w *kqueueWatcher) Events() <-chan fsnotify.Event { return w.events }
func (w *kqueueWatcher) Errors() <-chan error          { return w.errors }

func (w *kqueueWatcher) Add(dir string) error {
	dir = filepath.Clean(dir)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return fsnotify.ErrClosed
	}
	if _, ok := w.dirs[dir]; ok {
		return nil
	}
	fd, err := openNoWait(unix.AT_FDCWD, dir, unix.O_DIRECTORY)
	if err != nil {
		return fmt.Errorf("guardianwatch: watch %s: %w", dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("guardianwatch: watch %s: %w", dir, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return fmt.Errorf("guardianwatch: watch %s: not a directory", dir)
	}
	if err := w.register(fd); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("guardianwatch: watch %s: %w", dir, err)
	}
	d := &watchedDir{path: dir, fd: fd, files: map[string]*watchedFile{}}
	w.dirs[dir] = d
	w.byFD[fd] = watchRef{dir: d}
	for name := range w.files[dir] {
		w.startFile(d, name)
	}
	return nil
}

func (w *kqueueWatcher) Remove(dir string) error {
	dir = filepath.Clean(dir)
	w.mu.Lock()
	defer w.mu.Unlock()
	d, ok := w.dirs[dir]
	if !ok {
		return fmt.Errorf("%w: %s", fsnotify.ErrNonExistentWatch, dir)
	}
	w.dropDir(d)
	return nil
}

func (w *kqueueWatcher) SetFiles(paths []string) {
	next := map[string]map[string]struct{}{}
	for _, path := range paths {
		path = filepath.Clean(path)
		dir, name := filepath.Dir(path), filepath.Base(path)
		if !filepath.IsAbs(path) || dir == path || name == "." || name == ".." {
			continue
		}
		if next[dir] == nil {
			next[dir] = map[string]struct{}{}
		}
		next[dir][name] = struct{}{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.files = next
	for path, d := range w.dirs {
		names := next[path]
		for name, f := range d.files {
			if _, keep := names[name]; !keep {
				w.closeFile(f)
				delete(d.files, name)
			}
		}
		for name := range names {
			if _, ok := d.files[name]; !ok {
				w.startFile(d, name)
			}
		}
	}
}

func (w *kqueueWatcher) Close() error {
	w.once.Do(func() {
		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()
		// Wake the reader before releasing a blocked send: the reader
		// closes the pipe on its way out.
		_, _ = unix.Write(w.wake[1], []byte{0})
		close(w.done)
	})
	<-w.exited
	return nil
}

// startFile begins tracking name in d; its current state is the baseline
// and is not reported.
func (w *kqueueWatcher) startFile(d *watchedDir, name string) {
	f := &watchedFile{name: name, fd: -1}
	d.files[name] = f
	_ = w.refreshFile(d, f)
}

// refreshFile compares the entry with its last seen state, reports a
// creation, replacement or removal, and keeps a descriptor on it while it is
// a regular file. It never opens anything but a regular file.
func (w *kqueueWatcher) refreshFile(d *watchedDir, f *watchedFile) []fsnotify.Event {
	path := filepath.Join(d.path, f.name)
	var st unix.Stat_t
	if err := statNoFollow(d.fd, f.name, &st); err != nil {
		w.closeFile(f)
		if !f.exists {
			return nil
		}
		f.exists = false
		return []fsnotify.Event{{Name: path, Op: fsnotify.Remove}}
	}
	kind := st.Mode & unix.S_IFMT
	var events []fsnotify.Event
	if !f.exists || f.dev != st.Dev || f.ino != st.Ino || f.kind != kind {
		w.closeFile(f)
		f.exists, f.dev, f.ino, f.kind = true, st.Dev, st.Ino, kind
		events = append(events, fsnotify.Event{Name: path, Op: fsnotify.Create})
	}
	if f.fd < 0 && kind == unix.S_IFREG {
		w.openFile(d, f)
	}
	return events
}

// openFile opens the regular file f names for change notification. If the
// entry changed since refreshFile looked at it, it stays unwatched: the
// change is a directory event that brings refreshFile back to it.
func (w *kqueueWatcher) openFile(d *watchedDir, f *watchedFile) {
	fd, err := openNoWait(d.fd, f.name, 0)
	if err != nil {
		return
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != f.dev || st.Ino != f.ino {
		_ = unix.Close(fd)
		return
	}
	if w.register(fd) != nil {
		_ = unix.Close(fd)
		return
	}
	f.fd = fd
	w.byFD[fd] = watchRef{dir: d, file: f}
}

func (w *kqueueWatcher) closeFile(f *watchedFile) {
	if f.fd < 0 {
		return
	}
	delete(w.byFD, f.fd)
	_ = unix.Close(f.fd)
	f.fd = -1
}

func (w *kqueueWatcher) dropDir(d *watchedDir) {
	for _, f := range d.files {
		w.closeFile(f)
	}
	delete(w.byFD, d.fd)
	_ = unix.Close(d.fd)
	delete(w.dirs, d.path)
}

func (w *kqueueWatcher) register(fd int) error {
	var change [1]unix.Kevent_t
	unix.SetKevent(&change[0], fd, unix.EVFILT_VNODE, unix.EV_ADD|unix.EV_CLEAR|unix.EV_ENABLE)
	change[0].Fflags = noteFlags
	return w.kevent(change[:])
}

func (w *kqueueWatcher) kevent(changes []unix.Kevent_t) error {
	for {
		_, err := unix.Kevent(w.kq, changes, nil, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func (w *kqueueWatcher) readEvents() {
	defer w.shutdown()
	buffer := make([]unix.Kevent_t, 32)
	for {
		n, err := unix.Kevent(w.kq, nil, buffer, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if !w.sendError(fmt.Errorf("guardianwatch: read kqueue: %w", err)) {
				return
			}
			continue
		}
		var events []fsnotify.Event
		w.mu.Lock()
		for _, kev := range buffer[:n] {
			fd := int(kev.Ident)
			if fd == w.wake[0] {
				w.mu.Unlock()
				return
			}
			events = append(events, w.handle(fd, kev.Fflags)...)
		}
		w.mu.Unlock()
		for _, event := range events {
			if !w.sendEvent(event) {
				return
			}
		}
	}
}

// handle turns one kqueue event into watcher events. It runs with w.mu held
// and only makes calls that do not wait on the file system entries.
func (w *kqueueWatcher) handle(fd int, fflags uint32) []fsnotify.Event {
	ref, ok := w.byFD[fd]
	if !ok {
		return nil
	}
	d := ref.dir
	if ref.file == nil {
		if fflags&(unix.NOTE_DELETE|unix.NOTE_RENAME|unix.NOTE_REVOKE) != 0 {
			op := fsnotify.Remove
			if fflags&unix.NOTE_RENAME != 0 {
				op = fsnotify.Rename
			}
			w.dropDir(d)
			return []fsnotify.Event{{Name: d.path, Op: op}}
		}
		if fflags&(unix.NOTE_WRITE|unix.NOTE_EXTEND) == 0 {
			return nil
		}
		names := make([]string, 0, len(d.files))
		for name := range d.files {
			names = append(names, name)
		}
		sort.Strings(names)
		var events []fsnotify.Event
		for _, name := range names {
			events = append(events, w.refreshFile(d, d.files[name])...)
		}
		return events
	}
	f := ref.file
	path := filepath.Join(d.path, f.name)
	if fflags&(unix.NOTE_DELETE|unix.NOTE_RENAME|unix.NOTE_REVOKE) != 0 {
		op := fsnotify.Remove
		if fflags&unix.NOTE_RENAME != 0 {
			op = fsnotify.Rename
		}
		w.closeFile(f)
		f.exists = false
		// A rename over the file replaces it in one step, so look at the
		// entry again: a new file there is reported and watched.
		return append([]fsnotify.Event{{Name: path, Op: op}}, w.refreshFile(d, f)...)
	}
	var op fsnotify.Op
	if fflags&(unix.NOTE_WRITE|unix.NOTE_EXTEND) != 0 {
		op |= fsnotify.Write
	}
	if fflags&unix.NOTE_ATTRIB != 0 {
		op |= fsnotify.Chmod
	}
	if op == 0 {
		return nil
	}
	return []fsnotify.Event{{Name: path, Op: op}}
}

func (w *kqueueWatcher) sendEvent(event fsnotify.Event) bool {
	select {
	case w.events <- event:
		return true
	case <-w.done:
		return false
	}
}

func (w *kqueueWatcher) sendError(err error) bool {
	select {
	case w.errors <- err:
		return true
	case <-w.done:
		return false
	}
}

func (w *kqueueWatcher) shutdown() {
	w.mu.Lock()
	w.closed = true
	for _, d := range w.dirs {
		w.dropDir(d)
	}
	w.mu.Unlock()
	_ = unix.Close(w.kq)
	_ = unix.Close(w.wake[0])
	_ = unix.Close(w.wake[1])
	close(w.events)
	close(w.errors)
	close(w.exited)
}

func openNoWait(dirfd int, path string, flags int) (int, error) {
	for {
		fd, err := unix.Openat(dirfd, path, openFlags|flags, 0)
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

func statNoFollow(dirfd int, name string, st *unix.Stat_t) error {
	for {
		err := unix.Fstatat(dirfd, name, st, unix.AT_SYMLINK_NOFOLLOW)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}
