#!/usr/bin/env bash
# Secure Client golden: byte-for-byte fixtures for what the macOS Secure
# Client (AVC) installer renders. Production Secure Client ships this
# installer and it must not change when other deployment profiles are
# added. See testdata/secure_client_golden/README.md.
#
# Regenerate deliberately with:
#   UPDATE_SECURE_CLIENT_GOLDEN=1 packaging/macos/tests/run_tests.sh test_secure_client_golden.sh

. "${PKG_DIR}/lib/installer_lib.sh"

SC_GOLDEN_DIR="${REPO_ROOT}/testdata/secure_client_golden/macos"
SC_SUPPORT="/opt/cisco/secureclient/defenseclaw"
SC_PROD_ENDPOINT="https://us.api.inspect.aidefense.security.cisco.com"

_sc_golden_compare() {
  local name="$1" got="$2"
  local path="${SC_GOLDEN_DIR}/${name}"
  if [[ "${UPDATE_SECURE_CLIENT_GOLDEN:-}" == "1" ]]; then
    mkdir -p "${SC_GOLDEN_DIR}"
    printf '%s\n' "${got}" > "${path}"
    return 0
  fi
  if [[ ! -f "${path}" ]]; then
    _fail "missing Secure Client golden ${path}; regenerate with UPDATE_SECURE_CLIENT_GOLDEN=1"
    return 1
  fi
  local want
  want="$(cat "${path}")"
  if [[ "${got}" != "${want}" ]]; then
    local diff_out
    diff_out="$(diff <(printf '%s\n' "${want}") <(printf '%s\n' "${got}") | head -40)"
    _fail "Secure Client golden drift in macos/${name}. Production Secure Client behavior must not change; if intended, review and regenerate with UPDATE_SECURE_CLIENT_GOLDEN=1.
${diff_out}"
    return 1
  fi
}

_sc_discover_stub() {
  discover_agent_version() {
    case "$1" in
      amp)        printf '0.100.0' ;;
      codex)      printf '0.130.0' ;;
      claudecode) printf '2.5.0'   ;;
      cursor)     printf '3.14.27' ;;
      opencode)   printf '1.18.19' ;;
      *)          printf ''        ;;
    esac
  }
}

t_sc_golden_render_config_single() {
  _sc_golden_compare "render_config_action_cursor.yaml" \
    "$(render_config action cursor 18970 "${SC_SUPPORT}" "${SC_PROD_ENDPOINT}" cursor)"
}

t_sc_golden_render_config_multi_with_home_dirs() {
  _sc_golden_compare "render_config_observe_multi_home_dirs.yaml" \
    "$(render_config observe codex 18970 "${SC_SUPPORT}" "${SC_PROD_ENDPOINT}" \
      2 /Users/alice /Users/bob codex claudecode cursor amp opencode)"
}

t_sc_golden_render_targets() {
  _sc_discover_stub
  local users="alice:501:20:/Users/alice
bob:502:20:/Users/bob"
  _sc_golden_compare "render_targets_multi.yaml" \
    "$(render_targets_manifest "${SC_SUPPORT}" "codex,claudecode,cursor,amp,opencode,windsurf" "${users}")"
}

t_sc_golden_endpoints() {
  local out="" env ep rc
  for env in prod preview staging; do
    ep="$(aid_endpoint_for_env "${env}")" && rc=0 || rc=$?
    out+="aid_endpoint_for_env ${env} -> rc=${rc} endpoint=[${ep}]"$'\n'
  done
  for ep in "" "https://preview.api.inspect.aidefense.aiteam.cisco.com/" "http://insecure.example" "https://host/path" "https://[::1]:8443"; do
    local resolved
    resolved="$(resolve_aid_endpoint prod "${ep}")" && rc=0 || rc=$?
    out+="resolve_aid_endpoint prod '${ep}' -> rc=${rc} endpoint=[${resolved}]"$'\n'
  done
  _sc_golden_compare "aid_endpoints.txt" "${out%$'\n'}"
}

t_sc_golden_supported_connectors() {
  local out="" c
  for c in codex claudecode cursor amp opencode windsurf geminicli copilot hermes; do
    if is_supported_connector "${c}"; then out+="${c} supported"$'\n'; else out+="${c} unsupported"$'\n'; fi
  done
  _sc_golden_compare "supported_connectors.txt" "${out%$'\n'}"
}

run_case "secure client golden: render_config single connector" t_sc_golden_render_config_single
run_case "secure client golden: render_config multi connector with home dirs" t_sc_golden_render_config_multi_with_home_dirs
run_case "secure client golden: render_targets_manifest" t_sc_golden_render_targets
run_case "secure client golden: AI Defense endpoint selection" t_sc_golden_endpoints
run_case "secure client golden: supported connectors" t_sc_golden_supported_connectors
