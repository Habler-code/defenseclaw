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
	"sync"
	"testing"
)

// Output past the cap is discarded rather than failing the write, so exec
// keeps draining the pipes; one buffer may back both streams.
func TestLimitedBufferDiscardsPastTheLimitAndIsConcurrencySafe(t *testing.T) {
	buffer := newLimitedBuffer(10)
	if n, err := buffer.Write([]byte("0123456789abc")); err != nil || n != 13 {
		t.Fatalf("write past the limit = %d, %v; want 13, nil", n, err)
	}
	if got := buffer.String(); got != "0123456789" || !buffer.Truncated() {
		t.Fatalf("buffer = %q truncated=%v", got, buffer.Truncated())
	}
	shared := newLimitedBuffer(1 << 20)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = shared.Write([]byte("0123456789"))
				_ = shared.String()
			}
		}()
	}
	wg.Wait()
	if got := len(shared.String()); got != 8000 {
		t.Fatalf("concurrent writes lost bytes: %d", got)
	}
}
