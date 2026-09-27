//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A gateway that cannot start (e.g. a rule pack that does not load) must
// leave its reason in the result and in the lifecycle directory even though
// the rollback of a first install removes the log directory.
func TestFailedActivationKeepsTheGatewayOutput(t *testing.T) {
	h := newTestHost(t, "darwin")
	h.healthy = false
	health := h.env.HealthGet
	h.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
		log := h.env.P(h.env.gatewayErrorLogPath())
		_ = os.MkdirAll(filepath.Dir(log), 0o755)
		_ = os.WriteFile(log, []byte("starting\nguardrail: load rule pack /opt/x: rules/bad.yaml: invalid severity \"URGENT\"\x1b[0m\n"), 0o644)
		return health(ctx)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
	requireError(t, r, codeActivate)
	var message string
	for _, e := range r.Errors {
		if e.Code == codeActivate {
			message = e.Message
		}
	}
	if !strings.Contains(message, `invalid severity "URGENT"`) || strings.Contains(message, "\x1b") {
		t.Fatalf("activation error lacks the sanitized gateway reason: %q", message)
	}
	kept, err := os.ReadFile(h.env.activationFailurePath())
	if err != nil || !strings.Contains(string(kept), "invalid severity") {
		t.Fatalf("gateway output not kept after rollback: %v %q", err, kept)
	}
}

func TestGatewayOutputExcerptIsBounded(t *testing.T) {
	long := strings.Repeat("x", 1000)
	lines := []string{}
	for i := 0; i < 50; i++ {
		lines = append(lines, long)
	}
	excerpt := gatewayOutputExcerpt(strings.Join(lines, "\n"))
	if got := strings.Count(excerpt, " | ") + 1; got != gatewayExcerptLines {
		t.Fatalf("excerpt lines = %d", got)
	}
	if len(excerpt) > gatewayExcerptLines*(gatewayExcerptLineBytes+10) {
		t.Fatalf("excerpt too long: %d", len(excerpt))
	}
}
