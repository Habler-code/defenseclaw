// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

type verifiedUserScopedIdentityContextKey struct{}

// handleForeignHookSession keeps the standalone session snapshot in the
// gateway's data directory. The namespace comes only from hook-socket peer
// credentials or a per-user hook token authenticated by tokenAuth.
func (a *APIServer) handleForeignHookSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.userScopedCredentialsRequired() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	connector := strings.TrimPrefix(r.URL.Path, enterprisepolicy.ForeignHookSessionPathPrefix)
	if connector == "" || strings.Contains(connector, "/") || authenticatedHookConnector(r.Context()) != connector {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_scope_unverified")
		return
	}
	identity := ""
	if peer, ok := managedHookPeerFromContext(r.Context()); ok {
		identity = strconv.Itoa(peer.UID)
	} else {
		identity, _ = r.Context().Value(verifiedUserScopedIdentityContextKey{}).(string)
	}
	if identity == "" {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_identity_unverified")
		return
	}
	dataDir := strings.TrimSpace(a.configDataDir())
	if !filepath.IsAbs(dataDir) {
		writeManagedHookRefusal(w, http.StatusServiceUnavailable, "foreign_hook_session_store_unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var exchange enterprisepolicy.SessionExchange
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&exchange); err != nil {
		http.Error(w, "invalid session update", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "invalid session update", http.StatusBadRequest)
		return
	}
	if exchange.Key.Connector != connector {
		writeManagedHookRefusal(w, http.StatusForbidden, "foreign_hook_session_scope_mismatch")
		return
	}
	digest := sha256.Sum256([]byte(identity))
	stateDir := filepath.Join(dataDir, "foreign-hook-sessions", fmt.Sprintf("%x", digest[:20]))
	a.foreignHookSessionMu.Lock()
	decision := enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
		StateDir:     stateDir,
		Key:          exchange.Key,
		SessionStart: exchange.SessionStart,
		Decision:     exchange.Decision,
		Now:          time.Now(),
	})
	a.foreignHookSessionMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}
