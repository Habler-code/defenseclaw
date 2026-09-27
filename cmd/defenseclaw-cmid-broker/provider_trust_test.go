// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

type recordingLibrary struct {
	events *[]string
	closes int
}

func (library *recordingLibrary) Signer() cmidbroker.LibrarySigner {
	return cmidbroker.LibrarySigner{CommonName: cmidbroker.CMIDLibraryPublisher, CertificateSHA256: "ab"}
}

func (library *recordingLibrary) Close() error {
	library.closes++
	*library.events = append(*library.events, "release")
	return nil
}

type recordingProvider struct {
	events     *[]string
	library    *recordingLibrary
	refreshErr error
}

func (provider *recordingProvider) Token(context.Context) (string, error) { return "", nil }

func (provider *recordingProvider) Refresh(context.Context) error {
	if provider.library.closes != 0 {
		*provider.events = append(*provider.events, "refresh-after-release")
	} else {
		*provider.events = append(*provider.events, "refresh")
	}
	return provider.refreshErr
}

func (provider *recordingProvider) Invalidate() {}

type providerTrustCase struct {
	events   []string
	library  *recordingLibrary
	provider *recordingProvider
	log      bytes.Buffer
}

func newProviderTrustCase() *providerTrustCase {
	test := &providerTrustCase{}
	test.library = &recordingLibrary{events: &test.events}
	test.provider = &recordingProvider{events: &test.events, library: test.library}
	return test
}

func (test *providerTrustCase) steps(verifyErr, constructErr error) providerSteps {
	return providerSteps{
		verify: func(path string) (verifiedLibrary, error) {
			test.events = append(test.events, "verify "+path)
			if verifyErr != nil {
				return nil, verifyErr
			}
			return test.library, nil
		},
		construct: func(path string) (cmidbroker.Provider, error) {
			if test.library.closes != 0 {
				test.events = append(test.events, "construct-after-release "+path)
			} else {
				test.events = append(test.events, "construct "+path)
			}
			if constructErr != nil {
				return nil, constructErr
			}
			return test.provider, nil
		},
	}
}

func (test *providerTrustCase) run(t *testing.T, steps providerSteps) (cmidbroker.Provider, error) {
	t.Helper()
	return newVerifiedProvider(
		context.Background(),
		testLibraryPath,
		steps,
		log.New(&test.log, "", 0),
	)
}

const testLibraryPath = `C:\Program Files\Cisco\Cisco Secure Client\cmidapi.dll`

func TestVerifiedProviderLoadsTheLibraryWhileTheVerifiedFileIsHeld(t *testing.T) {
	test := newProviderTrustCase()
	provider, err := test.run(t, test.steps(nil, nil))
	if err != nil || provider != test.provider {
		t.Fatalf("newVerifiedProvider = %v, %v", provider, err)
	}
	want := []string{"verify " + testLibraryPath, "construct " + testLibraryPath, "refresh", "release"}
	if strings.Join(test.events, "|") != strings.Join(want, "|") {
		t.Fatalf("events = %q, want %q", test.events, want)
	}
	if test.library.closes != 1 {
		t.Fatalf("library released %d times, want once", test.library.closes)
	}
	if !strings.Contains(test.log.String(), "stage=provider-library-trust success=true") {
		t.Fatalf("trust stage not logged: %q", test.log.String())
	}
}

func TestVerifiedProviderNeverConstructsFromAnUnverifiedLibrary(t *testing.T) {
	test := newProviderTrustCase()
	rejected := errors.New("signer is not the publisher")
	provider, err := test.run(t, test.steps(rejected, nil))
	if provider != nil || !errors.Is(err, rejected) {
		t.Fatalf("newVerifiedProvider = %v, %v; want the verification error", provider, err)
	}
	if strings.Join(test.events, "|") != "verify "+testLibraryPath {
		t.Fatalf("events after a rejected library = %q, want verification only", test.events)
	}
	if !strings.Contains(test.log.String(), "stage=provider-library-trust success=false") {
		t.Fatalf("rejection not logged: %q", test.log.String())
	}

	// A verifier that reports success without a lease is not verification.
	test = newProviderTrustCase()
	steps := test.steps(nil, nil)
	steps.verify = func(string) (verifiedLibrary, error) { return nil, nil }
	if provider, err := test.run(t, steps); provider != nil || err == nil {
		t.Fatalf("newVerifiedProvider accepted a verifier without a lease: %v, %v", provider, err)
	}
	if len(test.events) != 0 {
		t.Fatalf("events without a lease = %q, want none", test.events)
	}

	for name, steps := range map[string]providerSteps{
		"no verification": {construct: test.steps(nil, nil).construct},
		"no construction": {verify: test.steps(nil, nil).verify},
	} {
		if provider, err := test.run(t, steps); provider != nil || err == nil {
			t.Fatalf("%s: newVerifiedProvider = %v, %v", name, provider, err)
		}
	}
}

func TestVerifiedProviderReleasesTheLibraryOnEveryFailure(t *testing.T) {
	test := newProviderTrustCase()
	if provider, err := test.run(t, test.steps(nil, errors.New("no factory"))); provider != nil || err == nil {
		t.Fatalf("construction failure: %v, %v", provider, err)
	}
	if test.library.closes != 1 || strings.Contains(strings.Join(test.events, "|"), "refresh") {
		t.Fatalf("construction failure events = %q, closes = %d", test.events, test.library.closes)
	}

	test = newProviderTrustCase()
	test.provider.refreshErr = errors.New("agent not ready")
	if provider, err := test.run(t, test.steps(nil, nil)); provider != nil || err == nil {
		t.Fatalf("refresh failure: %v, %v", provider, err)
	}
	want := []string{"verify " + testLibraryPath, "construct " + testLibraryPath, "refresh", "release"}
	if strings.Join(test.events, "|") != strings.Join(want, "|") || test.library.closes != 1 {
		t.Fatalf("refresh failure events = %q, closes = %d", test.events, test.library.closes)
	}
	if !strings.Contains(test.log.String(), "stage=provider-refresh success=false") {
		t.Fatalf("refresh failure not logged: %q", test.log.String())
	}
}

// The broker's source must build providers only through newVerifiedProvider:
// cloudreg.New only inside a providerSteps.construct function and
// cmidbroker.OpenTrustedLibrary only inside providerSteps.verify, with every
// providerSteps handed straight to newVerifiedProvider. A merge that restores
// a direct cloudreg.New -- for example a provider that discovers its library
// after start-up and constructs it itself -- fails here instead of silently
// loading cmidapi.dll on path trust alone.
func TestBrokerConstructsProvidersOnlyFromVerifiedLibraries(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "main_windows.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main_windows.go: %v", err)
	}
	counts := map[string]int{}
	var stack []ast.Node
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, node)
		switch typed := node.(type) {
		case *ast.CallExpr:
			for _, guarded := range []struct{ pkg, name, field string }{
				{"cloudreg", "New", "construct"},
				{"cmidbroker", "OpenTrustedLibrary", "verify"},
			} {
				if isPackageCall(typed, guarded.pkg, guarded.name) {
					counts[guarded.pkg+"."+guarded.name]++
					if !insideProviderStep(stack, guarded.field) {
						t.Errorf("%s: %s.%s is called outside providerSteps.%s",
							fileSet.Position(typed.Pos()), guarded.pkg, guarded.name, guarded.field)
					}
				}
			}
		case *ast.CompositeLit:
			if identName(typed.Type) == "providerSteps" {
				counts["providerSteps"]++
				parent, ok := stack[len(stack)-2].(*ast.CallExpr)
				if !ok || identName(parent.Fun) != "newVerifiedProvider" {
					t.Errorf("%s: providerSteps is not passed directly to newVerifiedProvider",
						fileSet.Position(typed.Pos()))
				}
			}
		}
		return true
	})
	for _, name := range []string{"cloudreg.New", "cmidbroker.OpenTrustedLibrary", "providerSteps"} {
		if counts[name] == 0 {
			t.Errorf("main_windows.go has no %s; the broker no longer builds a verified provider", name)
		}
	}
}

func isPackageCall(call *ast.CallExpr, pkg, name string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == name && identName(selector.X) == pkg
}

func identName(expression ast.Expr) string {
	if ident, ok := expression.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// insideProviderStep reports whether the innermost enclosing function literal
// is the value of field in a providerSteps composite literal.
func insideProviderStep(stack []ast.Node, field string) bool {
	for index := len(stack) - 1; index >= 2; index-- {
		function, ok := stack[index].(*ast.FuncLit)
		if !ok {
			continue
		}
		pair, ok := stack[index-1].(*ast.KeyValueExpr)
		if !ok || pair.Value != function || identName(pair.Key) != field {
			return false
		}
		literal, ok := stack[index-2].(*ast.CompositeLit)
		return ok && identName(literal.Type) == "providerSteps"
	}
	return false
}
