// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/spf13/cobra"
)

var (
	enterpriseACPClient      string
	enterpriseACPAgent       string
	enterpriseACPProfile     string
	enterpriseACPUser        string
	enterpriseACPUserHome    string
	enterpriseACPUID         int
	enterpriseACPGID         int
	enterpriseACPSID         string
	enterpriseACPUserDataDir string
	enterpriseACPJSON        bool
)

var enterpriseACPCmd = &cobra.Command{
	Use:   "acp",
	Short: "Provision and revoke managed per-user ACP credentials",
	Long: `Manage administrator-owned ACP enrollments for interactive users.

Each enrollment receives a unique bearer scoped to one principal, editor,
agent, and central policy profile. The service record remains in protected
machine state; only the bearer copy is published into the target user's private
ACP runtime. The gateway never writes an editor profile or user home.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return rootPersistentPreRunNoAuditE(cmd, args)
	},
}

var enterpriseACPEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Provision one exact user/client/agent ACP credential",
	RunE:  runEnterpriseACPEnroll,
}

var enterpriseACPVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify service and user copies for one ACP enrollment",
	RunE:  runEnterpriseACPVerify,
}

var enterpriseACPRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke one exact managed ACP credential",
	RunE:  runEnterpriseACPRevoke,
}

func init() {
	for _, command := range []*cobra.Command{enterpriseACPEnrollCmd, enterpriseACPVerifyCmd, enterpriseACPRevokeCmd} {
		command.Flags().StringVar(&enterpriseACPClient, "client", "", "ACP client ID (for example zed or jetbrains)")
		command.Flags().StringVar(&enterpriseACPAgent, "agent", "", "ACP agent ID (for example kiro)")
		command.Flags().StringVar(&enterpriseACPProfile, "profile", "", "Centrally configured ACP profile")
		command.Flags().StringVar(&enterpriseACPUser, "user", "", "Target local user name")
		command.Flags().StringVar(&enterpriseACPUserHome, "user-home", "", "Target user's home directory")
		command.Flags().IntVar(&enterpriseACPUID, "uid", -1, "Target Unix uid")
		command.Flags().IntVar(&enterpriseACPGID, "gid", -1, "Target Unix gid")
		command.Flags().StringVar(&enterpriseACPSID, "sid", "", "Target Windows user SID")
		command.Flags().StringVar(&enterpriseACPUserDataDir, "data-dir", "", "Per-user runtime data dir (default: <user-home>/.defenseclaw)")
		command.Flags().BoolVar(&enterpriseACPJSON, "json", false, "Emit machine-readable JSON")
	}
	enterpriseACPCmd.AddCommand(enterpriseACPEnrollCmd, enterpriseACPVerifyCmd, enterpriseACPRevokeCmd)
	enterpriseCmd.AddCommand(enterpriseACPCmd)
}

type enterpriseACPEnrollment struct {
	target    enterpriseHookTarget
	principal string
	dataDir   string
	client    string
	agent     string
	profile   string
}

func resolveEnterpriseACPEnrollment(requireAuthorization bool) (enterpriseACPEnrollment, error) {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return enterpriseACPEnrollment{}, errors.New("enterprise ACP enrollment requires deployment_mode: managed_enterprise")
	}
	client := strings.ToLower(strings.TrimSpace(enterpriseACPClient))
	agent := strings.ToLower(strings.TrimSpace(enterpriseACPAgent))
	profile := strings.TrimSpace(enterpriseACPProfile)
	if client == "" || agent == "" || profile == "" {
		return enterpriseACPEnrollment{}, errors.New("enterprise ACP enrollment requires --client, --agent, and --profile")
	}
	if _, err := acp.LookupAgent(agent); err != nil {
		return enterpriseACPEnrollment{}, err
	}
	clientKnown := false
	for _, item := range acp.BuiltinCatalog().Clients {
		if item.ID == client {
			clientKnown = true
			break
		}
	}
	if !clientKnown {
		return enterpriseACPEnrollment{}, fmt.Errorf("unknown ACP client: %s", client)
	}
	if requireAuthorization {
		clientBinding, clientOK := cfg.ACP.Clients[client]
		agentBinding, agentOK := cfg.ACP.Agents[agent]
		policy, profileOK := cfg.ACP.Profiles[profile]
		if !cfg.ACP.Enabled || !clientOK || !clientBinding.Enabled || clientBinding.Profile != profile ||
			!agentOK || !agentBinding.Enabled || agentBinding.Profile != profile || !profileOK ||
			!slices.Contains(policy.AllowedClients, client) || !slices.Contains(policy.AllowedAgents, agent) {
			return enterpriseACPEnrollment{}, fmt.Errorf(
				"central ACP policy does not explicitly authorize %s/%s in profile %s", client, agent, profile,
			)
		}
	}
	target, err := resolveEnterpriseHookTargetValues(
		enterpriseACPUser, enterpriseACPUserHome, enterpriseACPUID, enterpriseACPGID,
		enterpriseACPSID, enterpriseACPUserDataDir,
	)
	if err != nil {
		return enterpriseACPEnrollment{}, err
	}
	dataDir := strings.TrimSpace(enterpriseACPUserDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(target.home, ".defenseclaw")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return enterpriseACPEnrollment{}, fmt.Errorf("resolve target ACP data dir: %w", err)
	}
	homeAbs, err := filepath.Abs(target.home)
	if err != nil {
		return enterpriseACPEnrollment{}, err
	}
	relative, err := filepath.Rel(homeAbs, abs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return enterpriseACPEnrollment{}, errors.New("enterprise ACP per-user data dir must remain inside the target home")
	}
	principal := strings.TrimSpace(target.sid)
	if principal != "" {
		principal = "sid:" + strings.ToUpper(principal)
	} else if target.uid >= 0 {
		principal = fmt.Sprintf("uid:%d", target.uid)
	} else {
		hash := sha256.Sum256([]byte(filepath.Clean(homeAbs)))
		principal = "home:" + hex.EncodeToString(hash[:])
	}
	return enterpriseACPEnrollment{
		target: target, principal: principal, dataDir: abs, client: client, agent: agent, profile: profile,
	}, nil
}

func runEnterpriseACPEnroll(cmd *cobra.Command, _ []string) error {
	enrollment, err := resolveEnterpriseACPEnrollment(true)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	credential, err := acp.EnsureEnterpriseCredential(
		cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
	)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	if err := alignEnterpriseACPCredentialOwner(
		cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile, credential.Token,
	); err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	var published enterpriseACPUserTokenResult
	err = enterprisehooks.RunTargetOperation(
		enterpriseACPContext(cmd), enrollment.targetCredentials(), enterpriseACPPublishUserTokenOperation,
		enterpriseACPUserTokenRequest{
			DataDir: enrollment.dataDir, Client: enrollment.client, Agent: enrollment.agent, Token: credential.Token,
		}, &published,
	)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	tokenPath := published.TokenPath
	payload := map[string]any{
		"ok": true, "principal": enrollment.principal, "client": enrollment.client,
		"agent": enrollment.agent, "profile": enrollment.profile, "token_file": tokenPath,
		"next": enterpriseACPSetupCommand(enrollment, tokenPath),
	}
	return enterpriseACPResult(cmd, payload, nil)
}

func enterpriseACPSetupCommand(enrollment enterpriseACPEnrollment, tokenPath string) string {
	guard := "defenseclaw-acp"
	if executable, err := os.Executable(); err == nil {
		extension := filepath.Ext(executable)
		guard = filepath.Join(filepath.Dir(executable), "defenseclaw-acp"+extension)
	}
	activate := ""
	mode := strings.TrimSpace(cfg.ACP.Mode)
	if mode == "" {
		mode = "observe"
	}
	if profile, ok := cfg.ACP.Profiles[enrollment.profile]; ok && strings.TrimSpace(profile.Mode) != "" {
		mode = strings.TrimSpace(profile.Mode)
	}
	if mode == "action" {
		activate = " --activate"
	}
	return fmt.Sprintf(
		"defenseclaw acp setup --managed --client %s --agent %s --profile %s%s --runtime-data-dir %q --token-file %q --guard-binary %q",
		enrollment.client, enrollment.agent, enrollment.profile, activate, enrollment.dataDir, tokenPath, guard,
	)
}

func runEnterpriseACPVerify(cmd *cobra.Command, _ []string) error {
	enrollment, err := resolveEnterpriseACPEnrollment(false)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	credential, err := acp.LoadEnterpriseCredential(
		cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
	)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(enrollment.dataDir, enrollment.client, enrollment.agent)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	expected := sha256.Sum256([]byte(credential.Token))
	err = enterprisehooks.RunTargetOperation(
		enterpriseACPContext(cmd), enrollment.targetCredentials(), enterpriseACPVerifyUserTokenOperation,
		enterpriseACPUserTokenRequest{
			DataDir: enrollment.dataDir, Client: enrollment.client, Agent: enrollment.agent,
			TokenSHA256: hex.EncodeToString(expected[:]),
		}, nil,
	)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	return enterpriseACPResult(cmd, map[string]any{
		"ok": true, "principal": enrollment.principal, "client": enrollment.client,
		"agent": enrollment.agent, "profile": enrollment.profile, "token_file": tokenPath,
	}, nil)
}

func runEnterpriseACPRevoke(cmd *cobra.Command, _ []string) error {
	enrollment, err := resolveEnterpriseACPEnrollment(false)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	// Revoke centrally first. From this point a copied or cached bearer has no
	// authority even if user-side cleanup is interrupted.
	if err := acp.RemoveEnterpriseCredential(
		cfg.DataDir, enrollment.principal, enrollment.client, enrollment.agent, enrollment.profile,
	); err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(enrollment.dataDir, enrollment.client, enrollment.agent)
	if err != nil {
		return enterpriseACPResult(cmd, nil, err)
	}
	err = enterprisehooks.RunTargetOperation(
		enterpriseACPContext(cmd), enrollment.targetCredentials(), enterpriseACPRemoveUserTokenOperation,
		enterpriseACPUserTokenRequest{DataDir: enrollment.dataDir, Client: enrollment.client, Agent: enrollment.agent},
		nil,
	)
	payload := map[string]any{
		"ok": err == nil, "principal": enrollment.principal, "client": enrollment.client,
		"agent": enrollment.agent, "profile": enrollment.profile, "token_file": tokenPath,
		"centrally_revoked": true,
	}
	return enterpriseACPResult(cmd, payload, err)
}

// Target-user ACP token operations run with the enrolled user's own
// credentials: in a per-target worker when invoked by root on Unix, and under
// SID impersonation on Windows. Each derives its path from the enrollment
// scope inside the target's data directory.
const (
	enterpriseACPPublishUserTokenOperation = "acp.publish-user-token"
	enterpriseACPVerifyUserTokenOperation  = "acp.verify-user-token"
	enterpriseACPRemoveUserTokenOperation  = "acp.remove-user-token"
)

type enterpriseACPUserTokenRequest struct {
	DataDir     string `json:"data_dir"`
	Client      string `json:"client"`
	Agent       string `json:"agent"`
	Token       string `json:"token,omitempty"`
	TokenSHA256 string `json:"token_sha256,omitempty"`
}

type enterpriseACPUserTokenResult struct {
	TokenPath string `json:"token_path"`
}

func init() {
	enterprisehooks.RegisterTargetOperation(enterpriseACPPublishUserTokenOperation, publishEnterpriseACPUserToken)
	enterprisehooks.RegisterTargetOperation(enterpriseACPVerifyUserTokenOperation, verifyEnterpriseACPUserToken)
	enterprisehooks.RegisterTargetOperation(enterpriseACPRemoveUserTokenOperation, removeEnterpriseACPUserToken)
}

func (e enterpriseACPEnrollment) targetCredentials() enterprisehooks.TargetCredentials {
	return enterprisehooks.TargetCredentials{
		UserHome: e.target.home, UID: e.target.uid, GID: e.target.gid, SID: e.target.sid,
	}
}

func enterpriseACPContext(cmd *cobra.Command) context.Context {
	if cmd != nil && cmd.Context() != nil {
		return cmd.Context()
	}
	return context.Background()
}

func decodeEnterpriseACPUserTokenRequest(
	target enterprisehooks.TargetCredentials,
	payload json.RawMessage,
) (enterpriseACPUserTokenRequest, string, error) {
	var request enterpriseACPUserTokenRequest
	if err := enterprisehooks.DecodeTargetOperationRequest(payload, &request); err != nil {
		return request, "", fmt.Errorf("decode ACP user token request: %w", err)
	}
	home, err := filepath.Abs(target.UserHome)
	if err != nil {
		return request, "", err
	}
	dataDir, err := filepath.Abs(request.DataDir)
	if err != nil {
		return request, "", err
	}
	relative, err := filepath.Rel(home, dataDir)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return request, "", errors.New("enterprise ACP per-user data dir must remain inside the target home")
	}
	path, err := acp.EnterpriseUserTokenPath(dataDir, request.Client, request.Agent)
	if err != nil {
		return request, "", err
	}
	return request, path, nil
}

func publishEnterpriseACPUserToken(
	_ context.Context, target enterprisehooks.TargetCredentials, payload json.RawMessage,
) (any, error) {
	request, _, err := decodeEnterpriseACPUserTokenRequest(target, payload)
	if err != nil {
		return nil, err
	}
	path, err := acp.PublishEnterpriseUserToken(request.DataDir, request.Client, request.Agent, request.Token)
	if err != nil {
		return nil, err
	}
	return enterpriseACPUserTokenResult{TokenPath: path}, nil
}

func verifyEnterpriseACPUserToken(
	_ context.Context, target enterprisehooks.TargetCredentials, payload json.RawMessage,
) (any, error) {
	request, tokenPath, err := decodeEnterpriseACPUserTokenRequest(target, payload)
	if err != nil {
		return nil, err
	}
	expected, err := hex.DecodeString(request.TokenSHA256)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("ACP user token verification requires a SHA-256 digest")
	}
	if err := safefile.ValidatePrivateFile(tokenPath); err != nil {
		return nil, err
	}
	body, err := safefile.ReadRegularFileBounded(tokenPath, 16<<10)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256([]byte(strings.TrimSpace(string(body))))
	if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		return nil, errors.New("target-user ACP token does not match the protected service enrollment")
	}
	return struct{}{}, nil
}

func removeEnterpriseACPUserToken(
	_ context.Context, target enterprisehooks.TargetCredentials, payload json.RawMessage,
) (any, error) {
	_, tokenPath, err := decodeEnterpriseACPUserTokenRequest(target, payload)
	if err != nil {
		return nil, err
	}
	info, statErr := os.Lstat(tokenPath)
	if errors.Is(statErr, os.ErrNotExist) {
		return struct{}{}, nil
	}
	if statErr != nil {
		return nil, statErr
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing to remove unsafe ACP user token path")
	}
	if err := os.Remove(tokenPath); err != nil {
		return nil, err
	}
	return struct{}{}, nil
}

func enterpriseACPResult(cmd *cobra.Command, payload map[string]any, err error) error {
	if enterpriseACPJSON {
		if payload == nil {
			payload = map[string]any{"ok": false}
		}
		if err != nil {
			payload["ok"] = false
			payload["error"] = err.Error()
		}
		if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); encodeErr != nil {
			return encodeErr
		}
		if err != nil {
			return errors.New("enterprise ACP operation failed")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if next, ok := payload["next"].(string); ok {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s managed ACP credential enrolled\n  Next (as target user): %s\n", Style("✓", "fg=green", "bold"), next)
		return nil
	}
	if revoked, _ := payload["centrally_revoked"].(bool); revoked {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s managed ACP credential revoked\n", Style("✓", "fg=green", "bold"))
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "  %s managed ACP credential verified\n", Style("✓", "fg=green", "bold"))
	return nil
}
