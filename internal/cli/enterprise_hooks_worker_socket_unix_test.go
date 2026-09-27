//go:build !windows

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The per-user worker must carry the managed hook socket through its JSON
// request so the plugins it renders use the peer-authorized socket.
func TestEnterpriseHookWorkerOptionsCarryManagedHookSocket(t *testing.T) {
	in := enterprisehooks.InstallOptions{
		ConnectorName:     "opencode",
		ManagedHookSocket: "/run/defenseclaw-hook/hook.sock",
		ManagedServiceUID: 995,
	}
	out := enterpriseHookWorkerOptionsFrom(in).installOptions(nil)
	if out.ManagedHookSocket != in.ManagedHookSocket || out.ManagedServiceUID != in.ManagedServiceUID {
		t.Fatalf("worker round trip = %q/%d, want %q/%d", out.ManagedHookSocket, out.ManagedServiceUID, in.ManagedHookSocket, in.ManagedServiceUID)
	}
}
