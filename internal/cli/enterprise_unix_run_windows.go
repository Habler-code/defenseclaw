// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

// The unix lifecycle groups exist on Windows builds so documentation and
// help stay identical everywhere; they refuse to run.

func runUnixLifecycle(_ *cobra.Command, platform, _ string, _ *unixLifecycleOptions) error {
	return withExitCode(errors.New("`enterprise "+platform+"` manages Linux and macOS hosts; use `enterprise windows` on Windows"), 1639)
}

// runEnterpriseSecret is the Windows seam for `enterprise secret`; the
// Windows lifecycle stream implements the protected-DACL store.
func runEnterpriseSecret(*cobra.Command, string, *enterpriseSecretOptions) error {
	return withExitCode(errors.New("`enterprise secret` is not available on Windows in this build"), 1603)
}
