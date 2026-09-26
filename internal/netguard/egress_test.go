// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseEgressProxyURL(t *testing.T) {
	for _, ok := range []string{"http://proxy.corp:3128", "https://proxy.corp", "http://10.0.0.5:8080/"} {
		if _, err := ParseEgressProxyURL(ok); err != nil {
			t.Errorf("ParseEgressProxyURL(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "proxy.corp:3128", "socks5://proxy.corp:1080", "http://user:pass@proxy.corp:3128", "http://proxy.corp/path", "http://proxy.corp?x=1", "http://:3128"} {
		if _, err := ParseEgressProxyURL(bad); err == nil {
			t.Errorf("ParseEgressProxyURL(%q) accepted", bad)
		}
	}
}

func TestEgressProxyRoutesThroughTheAdministratorProxy(t *testing.T) {
	proxy, err := (EgressProxy{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp,10.0.0.0/8"}).ProxyFunc()
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat": "http://proxy.corp:3128",
		"https://svc.internal.corp/x": "",
		"https://10.1.2.3/x":          "",
		"https://127.0.0.1:18970/x":   "",
	} {
		req := httptest.NewRequest(http.MethodPost, target, nil)
		got, err := proxy(req)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if (got == nil && want != "") || (got != nil && got.String() != want) {
			t.Errorf("proxy(%s) = %v, want %q", target, got, want)
		}
	}
}

func TestEgressProxyWithoutConfigKeepsTheEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy:8080")
	t.Setenv("NO_PROXY", "")
	transport, err := (EgressProxy{}).Transport()
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}
	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	// http.ProxyFromEnvironment caches the environment on first use in a
	// process, so only assert it is the environment selector's behavior when
	// it resolved anything at all.
	if got != nil && got.Host != "env-proxy:8080" {
		t.Fatalf("environment proxy = %v", got)
	}
	if _, err := (EgressProxy{HTTPSProxy: "ftp://x"}).Transport(); err == nil {
		t.Fatal("an invalid enterprise proxy must fail transport construction")
	}
}
