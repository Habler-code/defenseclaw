// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// CleanupResult reports what the guardian removed from one user's config.
type CleanupResult struct {
	Removed    []Finding `json:"removed"`
	Reported   []Finding `json:"reported"`
	BackupDir  string    `json:"backup_dir,omitempty"`
	FilesTouch []string  `json:"files_touched,omitempty"`
}

// CleanUserForeignHooks removes unapproved foreign hooks and plugins from
// the USER-level vendor config of req.Connector when the policy says
// remove. It must run with the target user's own credentials (the guardian
// calls it through enterprisehooks.RunAsTarget or its per-user worker), so
// every read and write is limited by the user's kernel permissions and no
// root-privileged path walk touches the home. Originals are copied into
// <home>/.defenseclaw/foreign-hooks-backup/<connector>/<timestamp>/ before
// any change. Project files are never modified; their findings are
// reported. Codex TOML config is reported rather than rewritten so a user's
// comments and layout are never re-marshalled.
func CleanUserForeignHooks(req GuardRequest, now time.Time) (CleanupResult, error) {
	result := CleanupResult{}
	if !req.Policy.Guard || req.Policy.ForeignHooks != config.ForeignHooksRemove {
		return result, nil
	}
	if strings.TrimSpace(req.Home) == "" || !filepath.IsAbs(req.Home) {
		return result, errors.New("foreign-hook cleanup requires an absolute home directory")
	}
	backupDir := filepath.Join(req.Home, ".defenseclaw", "foreign-hooks-backup", req.Connector, now.UTC().Format("20060102T150405Z"))
	var errs []error
	for _, source := range guardSources(req) {
		if source.scope != ScopeUser {
			continue
		}
		switch source.format {
		case formatCodexTOML:
			data, exists, err := readGuardFile(source.path)
			if err != nil || !exists {
				continue
			}
			for _, finding := range scanCodexTOML(req, source, data) {
				if !finding.Allowed {
					result.Reported = append(result.Reported, finding)
				}
			}
		case formatPluginDir:
			for _, finding := range scanPluginDir(req, source) {
				if finding.Allowed || strings.HasPrefix(finding.Reason, "cannot verify") {
					if !finding.Allowed {
						result.Reported = append(result.Reported, finding)
					}
					continue
				}
				if err := movePluginAside(finding.Path, backupDir); err != nil {
					errs = append(errs, err)
					result.Reported = append(result.Reported, finding)
					continue
				}
				result.BackupDir = backupDir
				result.Removed = append(result.Removed, finding)
				result.FilesTouch = appendUnique(result.FilesTouch, finding.Path)
			}
		case formatFlatDir:
			entries, err := os.ReadDir(source.path)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
					continue
				}
				child := hookSource{scope: ScopeUser, path: filepath.Join(source.path, entry.Name()), format: formatFlat}
				if err := cleanJSONSource(req, child, backupDir, &result); err != nil {
					errs = append(errs, err)
				}
			}
		default:
			if err := cleanJSONSource(req, source, backupDir, &result); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return result, errors.Join(errs...)
}

// cleanJSONSource rewrites one user JSON file without its foreign entries.
func cleanJSONSource(req GuardRequest, source hookSource, backupDir string, result *CleanupResult) error {
	data, exists, err := readGuardFile(source.path)
	if err != nil {
		result.Reported = append(result.Reported, unreadableFinding(req, source, err))
		return nil
	}
	if !exists || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var findings []Finding
	if source.format == formatPluginList {
		findings = scanPluginList(req, source, data)
	} else {
		findings = scanJSONHooks(req, source, data)
	}
	remove := map[string]bool{}
	for _, finding := range findings {
		if finding.Allowed {
			continue
		}
		if strings.HasPrefix(finding.Reason, "cannot verify") {
			result.Reported = append(result.Reported, finding)
			continue
		}
		remove[finding.Digest] = true
		result.Removed = append(result.Removed, finding)
	}
	if len(remove) == 0 {
		return nil
	}
	doc, err := decodeOrderedObject(data)
	if err != nil {
		return err
	}
	if source.format == formatPluginList {
		value, _ := doc.get("plugin")
		list, _ := value.([]any)
		kept := make([]any, 0, len(list))
		for _, item := range list {
			if !remove[sha256Hex(canonicalJSON(item))] {
				kept = append(kept, item)
			}
		}
		doc.set("plugin", kept)
	} else {
		hooksValue, _ := doc.get("hooks")
		hooks, _ := hooksValue.(*object)
		if hooks == nil {
			return nil
		}
		for _, event := range append([]string(nil), hooks.keys...) {
			value, _ := hooks.get(event)
			list, _ := value.([]any)
			kept := make([]any, 0, len(list))
			for _, item := range list {
				if source.format == formatGrouped {
					group, ok := item.(*object)
					if !ok {
						kept = append(kept, item)
						continue
					}
					handlersValue, _ := group.get("hooks")
					handlers, _ := handlersValue.([]any)
					keptHandlers := make([]any, 0, len(handlers))
					for _, handler := range handlers {
						if !remove[sha256Hex(canonicalJSON(handler))] {
							keptHandlers = append(keptHandlers, handler)
						}
					}
					if len(keptHandlers) == 0 {
						continue
					}
					group.set("hooks", keptHandlers)
					kept = append(kept, group)
					continue
				}
				if !remove[sha256Hex(canonicalJSON(item))] {
					kept = append(kept, item)
				}
			}
			if len(kept) == 0 {
				hooks.delete(event)
			} else {
				hooks.set(event, kept)
			}
		}
	}
	rendered, err := encodeOrdered(doc)
	if err != nil {
		return err
	}
	if err := backupUserFile(source.path, data, backupDir); err != nil {
		return err
	}
	result.BackupDir = backupDir
	info, err := os.Lstat(source.path)
	if err != nil {
		return err
	}
	if err := rewriteUserFile(source.path, rendered, info.Mode().Perm()); err != nil {
		return err
	}
	result.FilesTouch = appendUnique(result.FilesTouch, source.path)
	return nil
}

func backupName(path string) string {
	return sha256Hex([]byte(path))[:12] + "-" + filepath.Base(path)
}

func backupUserFile(path string, data []byte, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fmt.Errorf("create foreign-hook backup directory: %w", err)
	}
	target := filepath.Join(backupDir, backupName(path))
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("back up %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	manifest := filepath.Join(backupDir, "SOURCES.txt")
	entry := fmt.Sprintf("%s\t%s\n", backupName(path), path)
	handle, err := os.OpenFile(manifest, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer handle.Close()
	_, err = handle.WriteString(entry)
	return err
}

func rewriteUserFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".defenseclaw-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func movePluginAside(path, backupDir string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to move symbolic link %s", path)
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	return os.Rename(path, filepath.Join(backupDir, backupName(path)))
}
