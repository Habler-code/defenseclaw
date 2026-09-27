// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package authenticode holds the signer identity rules shared by the
// Windows publisher checks: the Secure Client IPC peer check
// (internal/ipc) and the CMID broker's identity library check
// (internal/managed/cmidbroker). The enterprise lifecycle module
// (Get-DefenseClawCertificateCommonName in
// packaging/windows/DefenseClawEnterprise.psm1) applies the same
// common-name rule to Cisco payloads.
package authenticode

import (
	"encoding/asn1"
	"unicode/utf16"
	"unicode/utf8"
)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// subjectAttribute and subjectAttributeSET mirror X.509's
// AttributeTypeAndValue and RelativeDistinguishedName. Values stay raw so an
// attribute other than the common name cannot make the subject unreadable.
type subjectAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type subjectAttributeSET []subjectAttribute

// SubjectCommonName returns the one common name (CN attribute, 2.5.4.3) in a
// DER-encoded X.509 Name, or "" when the name is malformed, has no common
// name, has more than one, or has one that is not a UTF8String,
// PrintableString, IA5String, or BMPString.
//
// A publisher check compares this value, never crypto/x509's
// Name.CommonName (which keeps the last of several CN attributes) or the
// Windows simple display name (which falls back to the OU, O, or e-mail
// address for a subject without a CN).
func SubjectCommonName(rawSubject []byte) string {
	var name []subjectAttributeSET
	rest, err := asn1.Unmarshal(rawSubject, &name)
	if err != nil || len(rest) != 0 {
		return ""
	}
	commonName, found := "", 0
	for _, rdn := range name {
		for _, attribute := range rdn {
			if !attribute.Type.Equal(oidCommonName) {
				continue
			}
			value, ok := directoryString(attribute.Value)
			if !ok {
				return ""
			}
			commonName = value
			found++
		}
	}
	if found != 1 {
		return ""
	}
	return commonName
}

func directoryString(value asn1.RawValue) (string, bool) {
	if value.Class != asn1.ClassUniversal || value.IsCompound {
		return "", false
	}
	switch value.Tag {
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
		if !utf8.Valid(value.Bytes) {
			return "", false
		}
		return string(value.Bytes), true
	case asn1.TagBMPString:
		if len(value.Bytes)%2 != 0 {
			return "", false
		}
		units := make([]uint16, len(value.Bytes)/2)
		for index := range units {
			units[index] = uint16(value.Bytes[2*index])<<8 | uint16(value.Bytes[2*index+1])
		}
		return string(utf16.Decode(units)), true
	default:
		return "", false
	}
}
