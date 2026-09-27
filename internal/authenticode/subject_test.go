// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package authenticode

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

var (
	oidOrganization     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCountry          = asn1.ObjectIdentifier{2, 5, 4, 6}
)

func marshalSubject(t *testing.T, rdns pkix.RDNSequence) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}
	return encoded
}

func rawAttribute(t *testing.T, oid asn1.ObjectIdentifier, tag int, value []byte) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oid, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: value}})
	if err != nil {
		t.Fatalf("marshal attribute: %v", err)
	}
	return encoded
}

// wrapSubject encodes one RDN per attribute: SEQUENCE { SET { attribute } ... }.
func wrapSubject(t *testing.T, attributes ...[]byte) []byte {
	t.Helper()
	var sets []byte
	for _, attribute := range attributes {
		set, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attribute,
		})
		if err != nil {
			t.Fatal(err)
		}
		sets = append(sets, set...)
	}
	name, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: sets,
	})
	if err != nil {
		t.Fatal(err)
	}
	return name
}

// attributeWithExtra encodes an AttributeTypeAndValue with a third element.
func attributeWithExtra(t *testing.T, oid asn1.ObjectIdentifier, value, extra string) []byte {
	t.Helper()
	var elements []byte
	for _, element := range []interface{}{
		oid,
		asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagPrintableString, Bytes: []byte(value)},
		asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagPrintableString, Bytes: []byte(extra)},
	} {
		encoded, err := asn1.Marshal(element)
		if err != nil {
			t.Fatal(err)
		}
		elements = append(elements, encoded...)
	}
	encoded, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: elements,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bmp(value string) []byte {
	var out []byte
	for _, r := range value {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

// Windows' simple display name falls back from the CN to the OU, then the O,
// then the e-mail address. The pin reads the CN attribute itself, so a
// certificate without one cannot present its OU or O as the publisher.
func TestSubjectCommonNameReadsOnlyTheCommonNameAttribute(t *testing.T) {
	const cisco = "Cisco Systems, Inc."
	for name, test := range map[string]struct {
		subject []byte
		want    string
	}{
		"common name and organization": {
			subject: marshalSubject(t, pkix.Name{
				CommonName:   cisco,
				Organization: []string{cisco},
				Country:      []string{"US"},
			}.ToRDNSequence()),
			want: cisco,
		},
		"organizational unit only": {
			subject: marshalSubject(t, pkix.RDNSequence{
				{{Type: oidCountry, Value: "US"}},
				{{Type: oidOrganization, Value: "Example"}},
				{{Type: oidOrganizationUnit, Value: cisco}},
			}),
		},
		"organization only": {
			subject: marshalSubject(t, pkix.RDNSequence{
				{{Type: oidOrganization, Value: cisco}},
			}),
		},
		"two common names": {
			subject: marshalSubject(t, pkix.RDNSequence{
				{{Type: oidCommonName, Value: cisco}},
				{{Type: oidCommonName, Value: "Example"}},
			}),
		},
		"common name inside a multi-valued RDN": {
			subject: marshalSubject(t, pkix.RDNSequence{
				{{Type: oidOrganizationUnit, Value: "Build"}, {Type: oidCommonName, Value: cisco}},
			}),
			want: cisco,
		},
		"UTF8String common name": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagUTF8String, []byte(cisco))),
			want:    cisco,
		},
		"BMPString common name": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagBMPString, bmp(cisco))),
			want:    cisco,
		},
		"odd-length BMPString common name": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagBMPString, append(bmp(cisco), 0))),
		},
		"invalid UTF-8 common name": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagUTF8String, append([]byte(cisco), 0xff))),
		},
		"common name that is not a string": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagOctetString, []byte(cisco))),
		},
		"undecodable attribute other than the common name": {
			subject: wrapSubject(t,
				rawAttribute(t, oidOrganization, asn1.TagOctetString, []byte{0xff}),
				rawAttribute(t, oidCommonName, asn1.TagPrintableString, []byte(cisco)),
			),
			want: cisco,
		},
		"trailing data": {
			subject: append(marshalSubject(t, pkix.Name{CommonName: cisco}.ToRDNSequence()), 0),
		},
		"truncated": {
			subject: func() []byte {
				encoded := marshalSubject(t, pkix.Name{CommonName: cisco}.ToRDNSequence())
				return encoded[:len(encoded)-1]
			}(),
		},
		"empty": {},
		// The PowerShell reader refuses these subjects; the Go parser
		// refuses them too.
		"extra element in the common name attribute": {
			subject: wrapSubject(t, attributeWithExtra(t, oidCommonName, cisco, "Example")),
		},
		"extra element in another attribute": {
			subject: wrapSubject(t,
				attributeWithExtra(t, oidOrganization, "Example", "Example"),
				rawAttribute(t, oidCommonName, asn1.TagPrintableString, []byte(cisco)),
			),
		},
		"BMPString common name ending in a high surrogate": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagBMPString, append(bmp(cisco), 0xd8, 0x3d))),
		},
		"BMPString common name with a lone low surrogate": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagBMPString, append(append(bmp("Cisco"), 0xde, 0x00), bmp(" Systems, Inc.")...))),
		},
		"BMPString common name with a high surrogate before another character": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagBMPString, append(append(bmp("Cisco"), 0xd8, 0x3d), bmp(" Systems, Inc.")...))),
		},
		"BMPString common name with a surrogate pair": {
			subject: wrapSubject(t, rawAttribute(t, oidCommonName, asn1.TagBMPString, append(bmp(cisco), 0xd8, 0x3d, 0xde, 0x00))),
			want:    cisco + "\U0001F600",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := SubjectCommonName(test.subject); got != test.want {
				t.Fatalf("SubjectCommonName = %q, want %q", got, test.want)
			}
		})
	}
}
