// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path"
	"strconv"
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

// Import paths of the two steps newVerifiedProvider composes. The guard below
// matches on the path, so a renamed import is still recognised.
const (
	cloudregImportPath   = "github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	cmidbrokerImportPath = "github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

// guardedProviderSteps are the functions the broker may reach only from the
// providerSteps field that names them.
var guardedProviderSteps = []struct{ importPath, name, field string }{
	{cloudregImportPath, "New", "construct"},
	{cmidbrokerImportPath, "OpenTrustedLibrary", "verify"},
}

// The broker's source must build providers only through newVerifiedProvider:
// cloudreg.New only inside a providerSteps.construct function and
// cmidbroker.OpenTrustedLibrary only inside providerSteps.verify, with every
// providerSteps handed straight to newVerifiedProvider. Every non-test Go file
// in the package is checked, whatever its build constraints, so a merge that
// restores a direct cloudreg.New -- for example a provider that discovers its
// library after start-up and constructs it itself, in main_windows.go or a new
// file -- fails here instead of silently loading cmidapi.dll on path trust
// alone.
func TestBrokerConstructsProvidersOnlyFromVerifiedLibraries(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the broker package: %v", err)
	}
	fileSet := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	for _, problem := range providerConstructionProblems(fileSet, files) {
		t.Error(problem)
	}
}

// compliantBrokerSource builds its provider the way main_windows.go does.
const compliantBrokerSource = `package main

import (
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

func run() {
	newVerifiedProvider(nil, "", providerSteps{
		verify: func(path string) (verifiedLibrary, error) {
			return cmidbroker.OpenTrustedLibrary(path, nil)
		},
		construct: func(path string) (cmidbroker.Provider, error) {
			return cloudreg.New(cloudreg.Config{LibPath: path})
		},
	}, nil)
}
`

func TestProviderConstructionGuardFollowsTheImportAcrossFiles(t *testing.T) {
	for _, test := range []struct{ name, source, want string }{
		{
			name: "renamed import in another file",
			source: `package main

import registry "github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"

func deferred(path string) { _, _ = registry.New(registry.Config{LibPath: path}) }
`,
			want: "deferred.go:5:37: cloudreg.New is used outside providerSteps.construct",
		},
		{
			name: "function value",
			source: `package main

import "github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"

var open = cmidbroker.OpenTrustedLibrary
`,
			want: "deferred.go:5:12: cmidbroker.OpenTrustedLibrary is used outside providerSteps.verify",
		},
		{
			name: "dot import",
			source: `package main

import . "github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"

func deferred(path string) { _, _ = New(Config{LibPath: path}) }
`,
			want: "deferred.go:3:8: " + cloudregImportPath + " is dot-imported",
		},
		{
			name: "steps kept for later",
			source: `package main

var deferredSteps = providerSteps{}
`,
			want: "deferred.go:3:21: providerSteps is not passed directly to newVerifiedProvider",
		},
		{
			name: "unrelated package with the same name",
			source: `package main

import cloudreg "example.com/unrelated/cloudreg"

func deferred() { cloudreg.New() }
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fileSet := token.NewFileSet()
			var files []*ast.File
			for name, source := range map[string]string{
				"main_windows.go": compliantBrokerSource,
				"deferred.go":     test.source,
			} {
				file, err := parser.ParseFile(fileSet, name, source, parser.SkipObjectResolution)
				if err != nil {
					t.Fatalf("parse %s: %v", name, err)
				}
				files = append(files, file)
			}
			problems := providerConstructionProblems(fileSet, files)
			if test.want == "" {
				if len(problems) != 0 {
					t.Fatalf("problems = %q, want none", problems)
				}
				return
			}
			if len(problems) != 1 || !strings.HasPrefix(problems[0], test.want) {
				t.Fatalf("problems = %q, want one starting %q", problems, test.want)
			}
		})
	}
}

// providerConstructionProblems reports each use of a guarded function outside
// its providerSteps field, each providerSteps not handed straight to
// newVerifiedProvider, and a package that no longer builds a verified provider.
func providerConstructionProblems(fileSet *token.FileSet, files []*ast.File) []string {
	var problems []string
	counts := map[string]int{}
	for _, file := range files {
		imported := guardedImportNames(fileSet, file, &problems)
		var stack []ast.Node
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, node)
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				importPath, ok := imported[identName(typed.X)]
				if !ok {
					break
				}
				for _, step := range guardedProviderSteps {
					if step.importPath != importPath || typed.Sel.Name != step.name {
						continue
					}
					qualified := path.Base(importPath) + "." + step.name
					counts[qualified]++
					if !insideProviderStep(stack, step.field) {
						problems = append(problems, fmt.Sprintf("%s: %s is used outside providerSteps.%s",
							fileSet.Position(typed.Pos()), qualified, step.field))
					}
				}
			case *ast.CompositeLit:
				if identName(typed.Type) == "providerSteps" {
					counts["providerSteps"]++
					parent, ok := stack[len(stack)-2].(*ast.CallExpr)
					if !ok || identName(parent.Fun) != "newVerifiedProvider" {
						problems = append(problems, fmt.Sprintf(
							"%s: providerSteps is not passed directly to newVerifiedProvider",
							fileSet.Position(typed.Pos())))
					}
				}
			}
			return true
		})
	}
	for _, name := range []string{"cloudreg.New", "cmidbroker.OpenTrustedLibrary", "providerSteps"} {
		if counts[name] == 0 {
			problems = append(problems, fmt.Sprintf(
				"the broker package has no %s; it no longer builds a verified provider", name))
		}
	}
	return problems
}

// guardedImportNames maps the name each guarded package is imported under in
// file to its import path. A dot import is reported, because its calls are
// unqualified and cannot be told apart from the broker's own functions.
func guardedImportNames(fileSet *token.FileSet, file *ast.File, problems *[]string) map[string]string {
	names := map[string]string{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || (importPath != cloudregImportPath && importPath != cmidbrokerImportPath) {
			continue
		}
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		switch name {
		case "_":
			// Imported for its registration only; nothing can be called.
		case ".":
			*problems = append(*problems, fmt.Sprintf("%s: %s is dot-imported, so its calls cannot be checked",
				fileSet.Position(spec.Pos()), importPath))
		default:
			names[name] = importPath
		}
	}
	return names
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
