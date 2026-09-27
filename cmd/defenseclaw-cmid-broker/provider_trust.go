// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

// providerReadyTimeout bounds the provider's first refresh, which is where
// the native library is loaded.
const providerReadyTimeout = 20 * time.Second

// verifiedLibrary is a Cloud Management identity library whose Authenticode
// signer has been verified and which cannot be written, renamed, or deleted
// until Close.
type verifiedLibrary interface {
	Signer() cmidbroker.LibrarySigner
	Close() error
}

// providerSteps are the platform steps newVerifiedProvider composes. On
// Windows, verify is cmidbroker.OpenTrustedLibrary and construct is
// cloudreg.New. They are fields so the order can be tested without a signed
// library.
type providerSteps struct {
	verify    func(path string) (verifiedLibrary, error)
	construct func(path string) (cmidbroker.Provider, error)
}

// newVerifiedProvider is the only way the broker turns a library path into a
// provider. It verifies the library, constructs the provider for that path,
// and runs the provider's first refresh -- which loads the native library --
// while the verified file still cannot be replaced; only then is the file
// released.
//
// Build every provider through here, including one for a library the broker
// resolves after it starts (Cloud Management installed or moved cmidapi.dll):
// the path is a parameter so each adopted library is verified before it is
// loaded. TestBrokerConstructsProvidersOnlyFromVerifiedLibraries fails if the
// broker reaches cloudreg.New any other way.
func newVerifiedProvider(
	ctx context.Context,
	path string,
	steps providerSteps,
	logger *log.Logger,
) (cmidbroker.Provider, error) {
	if steps.verify == nil || steps.construct == nil {
		return nil, errors.New("managed CMID provider requires library verification and construction steps")
	}
	library, err := steps.verify(path)
	if err == nil && library == nil {
		err = errors.New("library verification returned no lease")
	}
	if err != nil {
		logger.Printf("stage=provider-library-trust success=false error=%q", err.Error())
		return nil, fmt.Errorf("managed CMID library rejected: %w", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if closeErr := library.Close(); closeErr != nil {
			logger.Print("stage=provider-library-release success=false")
		}
	}
	defer release()
	signer := library.Signer()
	logger.Printf(
		"stage=provider-library-trust success=true signer=%q signer_sha256=%s",
		signer.CommonName,
		signer.CertificateSHA256,
	)

	provider, err := steps.construct(path)
	if err != nil || provider == nil {
		logger.Print("stage=provider-construction success=false")
		return nil, errors.New("managed CMID provider construction failed")
	}
	refreshCtx, cancel := context.WithTimeout(ctx, providerReadyTimeout)
	err = provider.Refresh(refreshCtx)
	cancel()
	release()
	if err != nil {
		logger.Print("stage=provider-refresh success=false category=cmid_refresh_failed")
		return nil, errors.New("managed CMID provider readiness failed")
	}
	return provider, nil
}
