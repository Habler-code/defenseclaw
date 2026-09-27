//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import "testing"

func TestParseNSSwitchDirectoryConfigured(t *testing.T) {
	for content, want := range map[string]bool{
		"passwd: files systemd\ngroup: files systemd\n":         false,
		"passwd:     sss files systemd\n":                       true, // RHEL 9 authselect default
		"passwd: files ldap\n":                                  true,
		"passwd: compat\n":                                      true, // compat can pull NIS entries
		"passwd: files [NOTFOUND=return] winbind\n":             true,
		"# passwd: sss\npasswd: files # sss later\n":            false,
		"group: sss files\n":                                    false, // glibc default for passwd is files
		"passwd: files mymachines systemd\nshadow: files sss\n": false,
		"passwd:files\n":                                        false,
		"passwd: files usrfiles extrausers altfiles db\n":       false,
		"passwd: files nis\n":                                   true,
		"hosts: files dns\npasswd: files sss\npasswd: files\n":  true, // first passwd line wins
	} {
		if got := ParseNSSwitchDirectoryConfigured(content); got != want {
			t.Errorf("ParseNSSwitchDirectoryConfigured(%q) = %v, want %v", content, got, want)
		}
	}
}

func TestParseLocalPasswdAndDSCL(t *testing.T) {
	local := parseLocalPasswd("root:x:0:0:root:/root:/bin/bash\n+nisuser::::::\nalice:x:1000:1000::/home/alice:/bin/bash\nbroken\nalice:x:2000:2000::/x:/bin/sh\n")
	if len(local) != 2 || local["alice"] != 1000 || local["root"] != 0 {
		t.Fatalf("parseLocalPasswd = %v", local)
	}
	dscl := parseDSCLLocalAccounts("_www 70\nalice   501\nnobody -2\nbad line here\n")
	if dscl["alice"] != 501 || dscl["nobody"] != -2 || dscl["_www"] != 70 || len(dscl) != 3 {
		t.Fatalf("parseDSCLLocalAccounts = %v", dscl)
	}
}
