// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/authenticode"
)

const maxLibrarySignerCertificateBytes = 64 << 10

// LibraryLease holds the Cloud Management identity library open without write
// or delete sharing. While it is held, the file at the verified path cannot be
// modified, renamed, or replaced, so a LoadLibrary of that path maps the bytes
// whose signature was verified.
type LibraryLease struct {
	once   sync.Once
	handle windows.Handle
	path   string
	signer LibrarySigner
}

// Path is the verified library path.
func (lease *LibraryLease) Path() string { return lease.path }

// Signer is the certificate that signed the verified library.
func (lease *LibraryLease) Signer() LibrarySigner { return lease.signer }

// Close releases the library handle. It is safe to call more than once.
func (lease *LibraryLease) Close() error {
	if lease == nil {
		return nil
	}
	var err error
	lease.once.Do(func() {
		if lease.handle != 0 && lease.handle != windows.InvalidHandle {
			err = windows.CloseHandle(lease.handle)
		}
		lease.handle = 0
	})
	return err
}

// OpenTrustedLibrary verifies the Cloud Management identity library
// immediately before it is loaded. It applies validatePath (the deployment's
// path trust), opens the file without write or delete sharing, re-applies
// validatePath while the handle is held, verifies the Authenticode signature
// of the open file with WinVerifyTrust, and requires the one common name in
// the signer certificate's subject to be CMIDLibraryPublisher. The caller
// holds the returned lease until the library has been loaded.
func OpenTrustedLibrary(path string, validatePath func(string) error) (*LibraryLease, error) {
	return openTrustedLibrary(path, validatePath, CheckLibrarySigner)
}

func openTrustedLibrary(
	path string,
	validatePath func(string) error,
	checkSigner func(LibrarySigner) error,
) (*LibraryLease, error) {
	if validatePath == nil || checkSigner == nil {
		return nil, errors.New("cmid library trust requires path and signer policies")
	}
	if err := validatePath(path); err != nil {
		return nil, err
	}
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode the Cloud Management identity library path: %w", err)
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		// Readers only: LoadLibrary opens for read/execute and is admitted,
		// while writers, renames, and deletes are refused until Close.
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open the Cloud Management identity library for verification: %w", err)
	}
	lease := &LibraryLease{handle: handle, path: path}
	keep := false
	defer func() {
		if !keep {
			_ = lease.Close()
		}
	}()

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return nil, fmt.Errorf("inspect the Cloud Management identity library: %w", err)
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return nil, errors.New("the Cloud Management identity library is not a regular file")
	}
	// The ancestry and ACLs are checked again while no writer can hold or
	// obtain the file, so the verified bytes are the ones at the trusted path.
	if err := validatePath(path); err != nil {
		return nil, err
	}
	signer, err := verifyLibraryAuthenticode(pathPointer, handle)
	if err != nil {
		return nil, err
	}
	if err := checkSigner(signer); err != nil {
		return nil, err
	}
	lease.signer = signer
	keep = true
	return lease, nil
}

func verifyLibraryAuthenticode(path *uint16, handle windows.Handle) (LibrarySigner, error) {
	// The broker starts at boot, possibly before the network. VerifyFile does
	// not fetch revocation, so availability does not depend on it; the chain,
	// file digest, and timestamp are still verified. It checks the exact open
	// file rather than re-resolving the path.
	verification, verifyErr := authenticode.VerifyFile(path, handle)
	var signer LibrarySigner
	var signerErr error
	if verifyErr == nil {
		signer, signerErr = verifiedLibrarySigner(verification)
	}
	closeErr := verification.Close()
	runtime.KeepAlive(path)
	if verifyErr != nil {
		return LibrarySigner{}, fmt.Errorf("%w: %v", ErrLibrarySignature, verifyErr)
	}
	if signerErr != nil {
		return LibrarySigner{}, fmt.Errorf("%w: %v", ErrLibrarySignature, signerErr)
	}
	if closeErr != nil {
		return LibrarySigner{}, fmt.Errorf("close WinVerifyTrust state: %w", closeErr)
	}
	return signer, nil
}

// verifiedLibrarySigner reads the leaf certificate of the primary signer that
// WinVerifyTrust just verified. It must run before the state is closed.
func verifiedLibrarySigner(verification *authenticode.Verification) (LibrarySigner, error) {
	certificate, err := verification.PrimarySignerCertificate()
	if err != nil {
		return LibrarySigner{}, err
	}
	return librarySignerFromContext(certificate)
}

// librarySignerFromContext identifies a signer certificate by the common name
// in its encoded subject and by the SHA-256 of its DER encoding.
func librarySignerFromContext(context *windows.CertContext) (LibrarySigner, error) {
	if context == nil || context.EncodedCert == nil || context.Length == 0 ||
		context.Length > maxLibrarySignerCertificateBytes {
		return LibrarySigner{}, errors.New("WinVerifyTrust returned an invalid signer certificate encoding")
	}
	encoded := make([]byte, context.Length)
	copy(encoded, unsafe.Slice(context.EncodedCert, context.Length))
	digest := sha256.Sum256(encoded)
	return LibrarySigner{
		CommonName:        authenticode.SubjectCommonName(certificateSubject(context)),
		CertificateSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

// certificateSubject copies the DER-encoded subject name of the certificate,
// or returns nil when Windows reports none or one outside the certificate.
func certificateSubject(context *windows.CertContext) []byte {
	info := context.CertInfo
	if info == nil || info.Subject.Data == nil || info.Subject.Size == 0 ||
		info.Subject.Size > context.Length {
		return nil
	}
	subject := make([]byte, info.Subject.Size)
	copy(subject, unsafe.Slice(info.Subject.Data, info.Subject.Size))
	return subject
}
