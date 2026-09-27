// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"
	"unicode/utf16"
)

var (
	testOIDCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
	testOIDOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}
	testOIDCountry      = asn1.ObjectIdentifier{2, 5, 4, 6}
)

// signerCertificateWithSubject returns a self-signed code-signing
// certificate whose subject is exactly subject, in order.
func signerCertificateWithSubject(t *testing.T, subject pkix.RDNSequence) []byte {
	t.Helper()
	rawSubject, err := asn1.Marshal(subject)
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		RawSubject:   rawSubject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return encoded
}

// The IPC peer check reads the signer's common name with the rule the
// CMID broker and the enterprise lifecycle module use: exactly one CN
// attribute. crypto/x509's Name.CommonName keeps the last of several,
// so a subject ending in CN=Cisco Systems, Inc. must not be admitted
// on that value.
func TestWindowsImageSignerRequiresOneSubjectCommonName(t *testing.T) {
	policy := testWindowsPeerPolicy(t)
	organization := pkix.RelativeDistinguishedNameSET{{Type: testOIDOrganization, Value: testCiscoSigner}}
	commonName := func(value string) pkix.RelativeDistinguishedNameSET {
		return pkix.RelativeDistinguishedNameSET{{Type: testOIDCommonName, Value: value}}
	}
	for name, test := range map[string]struct {
		subject pkix.RDNSequence
		want    string
	}{
		"one Cisco common name": {
			subject: pkix.RDNSequence{
				{{Type: testOIDCountry, Value: "US"}},
				organization,
				commonName(testCiscoSigner),
			},
			want: testCiscoSigner,
		},
		"Cisco common name after another common name": {
			subject: pkix.RDNSequence{organization, commonName("Example Publisher"), commonName(testCiscoSigner)},
		},
		"Cisco common name before another common name": {
			subject: pkix.RDNSequence{organization, commonName(testCiscoSigner), commonName("Example Publisher")},
		},
		"two common names in one RDN": {
			subject: pkix.RDNSequence{
				organization,
				{{Type: testOIDCommonName, Value: "Example Publisher"}, {Type: testOIDCommonName, Value: testCiscoSigner}},
			},
		},
		"Cisco organization without a common name": {
			subject: pkix.RDNSequence{organization},
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded := signerCertificateWithSubject(t, test.subject)
			signer, err := windowsImageSignerFromCertificate(encoded)
			if err != nil {
				t.Fatalf("windowsImageSignerFromCertificate: %v", err)
			}
			digest := sha256.Sum256(encoded)
			if signer.ThumbprintSHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("thumbprint = %s, want the DER certificate digest", signer.ThumbprintSHA256)
			}
			if !slices.Equal(signer.Organizations, []string{testCiscoSigner}) {
				t.Fatalf("organizations = %q, want [%q]", signer.Organizations, testCiscoSigner)
			}
			if signer.CommonName != test.want {
				t.Fatalf("common name = %q, want %q", signer.CommonName, test.want)
			}
			reason := policy.signerRejection(signer)
			if test.want != "" {
				if reason != "" {
					t.Fatalf("signer %+v rejected: %s", signer, reason)
				}
				return
			}
			if reason != "peer image signer has no subject common name" {
				t.Fatalf("signer %+v: rejection = %q, want the common-name refusal", signer, reason)
			}
		})
	}

	// Go's x509 parser drops a trailing NUL from a BMPString; the shared
	// parser keeps it, as the broker and the lifecycle module do, so the
	// name no longer matches the allowed signer.
	t.Run("BMPString common name with a trailing NUL", func(t *testing.T) {
		units := utf16.Encode([]rune(testCiscoSigner + "\x00"))
		value := make([]byte, 0, 2*len(units))
		for _, unit := range units {
			value = append(value, byte(unit>>8), byte(unit))
		}
		bmp := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagBMPString, Bytes: value}
		encoded := signerCertificateWithSubject(t, pkix.RDNSequence{
			organization,
			{{Type: testOIDCommonName, Value: bmp}},
		})
		signer, err := windowsImageSignerFromCertificate(encoded)
		if err != nil {
			t.Fatalf("windowsImageSignerFromCertificate: %v", err)
		}
		if want := testCiscoSigner + "\x00"; signer.CommonName != want {
			t.Fatalf("common name = %q, want %q", signer.CommonName, want)
		}
		want := fmt.Sprintf("peer image signer %q is not allowed", testCiscoSigner+"\x00")
		if reason := policy.signerRejection(signer); reason != want {
			t.Fatalf("rejection = %q, want %q", reason, want)
		}
	})

	if _, err := windowsImageSignerFromCertificate([]byte{0x30, 0x00}); err == nil {
		t.Fatal("windowsImageSignerFromCertificate accepted a malformed certificate")
	}
}
