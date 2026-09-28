// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The hook audit envelope schema sets additionalProperties false, so the
// caller keys a standalone hook row carries must be declared there.
func TestHookAuditEnvelopeSchemaDeclaresTheCallerKeys(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schemas", "hook-audit-envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatal("premise: the envelope schema refuses undeclared keys")
	}
	for _, key := range []string{auditUserIDKey, auditUserIDKindKey, auditUserNameKey} {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("hook-audit-envelope.json does not declare %q", key)
		}
	}
}
