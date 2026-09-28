// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const helperProcessEnv = "DEFENSECLAW_SENSOR_HELPER_TEST_PROCESS"

// TestSensorHelperProcess is not a test: runHelperBinary re-executes the test
// binary here to run main() with the arguments after "--", exactly as the
// service manager runs the helper.
func TestSensorHelperProcess(t *testing.T) {
	if os.Getenv(helperProcessEnv) != "1" {
		return
	}
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Args = append([]string{"defenseclaw-sensor-helper"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	os.Exit(0)
}

func runHelperBinary(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSensorHelperProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), helperProcessEnv+"=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("helper %v did not exit: stderr %q", args, errOut.String())
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		exitCode = exitErr.ExitCode()
	default:
		t.Fatalf("run helper %v: %v", args, err)
	}
	return out.String(), errOut.String(), exitCode
}

// The administrator checks which build the privileged helper runs the same
// way as for the gateway, without starting a second helper.
func TestVersionFlagPrintsTheBuildAndExits(t *testing.T) {
	stdout, stderr, code := runHelperBinary(t, "--version")
	if code != 0 {
		t.Fatalf("--version exited %d: %q", code, stderr)
	}
	if stdout != "defenseclaw-sensor-helper version dev (commit=unknown)\n" {
		t.Fatalf("--version printed %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("--version wrote to stderr: %q", stderr)
	}
}

func TestVersionStringNamesTheStampedBuild(t *testing.T) {
	defer func(v, c string) { version, commit = v, c }(version, commit)
	version, commit = "9.9.11", "438bd2fb"
	if got, want := versionString(), "defenseclaw-sensor-helper version 9.9.11 (commit=438bd2fb)"; got != want {
		t.Fatalf("versionString() = %q, want %q", got, want)
	}
}

// Every release build of the helper stamps the version and commit that
// --version and the "sensor helper starting" log line report.
func TestReleaseBuildsStampTheHelperVersionAndCommit(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	builds := regexp.MustCompile(`(?m)^  - id: `).Split(string(data), -1)
	found := 0
	for _, build := range builds {
		if !strings.Contains(build, "main: ./cmd/defenseclaw-sensor-helper\n") {
			continue
		}
		found++
		for _, stamp := range []string{"-X main.version={{.Version}}", "-X main.commit={{.Commit}}"} {
			if !strings.Contains(build, stamp) {
				t.Errorf("goreleaser build %q lacks %s", strings.SplitN(build, "\n", 2)[0], stamp)
			}
		}
	}
	if found == 0 {
		t.Fatal(".goreleaser.yaml has no defenseclaw-sensor-helper build")
	}
}
