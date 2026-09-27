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
// encoding/asn1 ignores elements after the last field of a SEQUENCE, so Extra
// catches a third element, which AttributeTypeAndValue does not have.
type subjectAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
	Extra asn1.RawValue `asn1:"optional"`
}

type subjectAttributeSET []subjectAttribute

// SubjectCommonName returns the one common name (CN attribute, 2.5.4.3) in a
// DER-encoded X.509 Name, or "" when the name is malformed, has no common
// name, has more than one, or has one that is not a UTF8String,
// PrintableString, IA5String, or BMPString. A name is malformed when any
// attribute holds more than a type and a value, and a common name is not a
// string when it is invalid UTF-8 or a BMPString with an odd length or an
// unpaired surrogate. These are the subjects the PowerShell reader
// (Get-DefenseClawCertificateCommonName) refuses.
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
			if len(attribute.Extra.FullBytes) != 0 {
				return ""
			}
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
		// utf16.Decode turns an unpaired surrogate into U+FFFD; refuse it
		// instead, as a strict UTF-16 decoder does.
		for index := 0; index < len(units); index++ {
			if !utf16.IsSurrogate(rune(units[index])) {
				continue
			}
			if index+1 < len(units) &&
				utf16.DecodeRune(rune(units[index]), rune(units[index+1])) != utf8.RuneError {
				index++
				continue
			}
			return "", false
		}
		return string(utf16.Decode(units)), true
	default:
		return "", false
	}
}
