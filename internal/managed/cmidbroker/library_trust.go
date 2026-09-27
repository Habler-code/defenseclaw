// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"errors"
	"fmt"
)

// CMIDLibraryPublisher is the Authenticode publisher of the Cisco Secure
// Client Cloud Management identity library (cmidapi.dll). It is compared with
// the one common name (CN attribute) in the signer certificate's subject, the
// same rule the enterprise lifecycle module, its installer, and Setup
// assembly apply.
const CMIDLibraryPublisher = "Cisco Systems, Inc."

var (
	// ErrLibrarySignature reports a library whose Authenticode signature is
	// missing, invalid, or does not chain to a trusted root.
	ErrLibrarySignature = errors.New("the Cloud Management identity library has no valid Authenticode signature")
	// ErrLibrarySigner reports a validly signed library from a publisher
	// other than CMIDLibraryPublisher.
	ErrLibrarySigner = errors.New("the Cloud Management identity library is not signed by " + CMIDLibraryPublisher)
)

// LibrarySigner identifies the certificate that produced a library's verified
// Authenticode signature.
type LibrarySigner struct {
	// CommonName is the one common name (CN attribute) in the signer
	// certificate's subject, or "" when the subject has none, more than one,
	// or one that is not a string (authenticode.SubjectCommonName, the rule
	// the Secure Client IPC peer check applies too). The simple display name
	// is not used: for a subject without a CN, Windows displays its OU, O, or
	// e-mail address instead, so it would let OU=Cisco Systems, Inc. pass as
	// the publisher.
	CommonName string
	// CertificateSHA256 is the lowercase hex SHA-256 of the DER certificate.
	CertificateSHA256 string
}

// CheckLibrarySigner accepts only the Cisco Secure Client publisher. The
// comparison is exact: a case-folded or punctuation near miss is a different
// publisher.
func CheckLibrarySigner(signer LibrarySigner) error {
	if signer.CommonName == "" {
		return fmt.Errorf(
			"%w: signer certificate has no single subject common name (certificate SHA-256 %s)",
			ErrLibrarySigner,
			signer.CertificateSHA256,
		)
	}
	if signer.CommonName != CMIDLibraryPublisher {
		return fmt.Errorf(
			"%w: signer is %q (certificate SHA-256 %s)",
			ErrLibrarySigner,
			signer.CommonName,
			signer.CertificateSHA256,
		)
	}
	return nil
}
