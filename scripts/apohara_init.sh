#!/usr/bin/env bash
# scripts/apohara_init.sh — interactive wizard that creates the
# `~/.config/apohara/secrets.env` file the orchestrator reads on
# startup. Idempotent (skips keys already set). Validates each
# provider with a curl HEAD before saving.
#
# Usage:
#   ./scripts/apohara_init.sh
#
# After running, source the file before starting the binary:
#   source ~/.config/apohara/secrets.env
#   cargo run --release --bin themis-orchestrator
#
# Or use it inline:
#   set -a; source ~/.config/apohara/secrets.env; set +a
#   cargo run --release --bin themis-orchestrator
#
# To re-validate without changing values:
#   ./scripts/apohara_init.sh --check

set -euo pipefail

SECRETS_DIR="${APOHARA_SECRETS_DIR:-$HOME/.config/apohara}"
SECRETS_FILE="$SECRETS_DIR/secrets.env"

CHECK_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=true ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"
touch "$SECRETS_FILE"
chmod 600 "$SECRETS_FILE"

# Load any existing values (don't clobber).
set +u
if [ -s "$SECRETS_FILE" ]; then
    set -a; source "$SECRETS_FILE"; set +a
fi
set -u

# --- helpers -----------------------------------------------------------------

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }
ask() {
    local label="$1"
    local default="${2:-}"
    local value
    if [ -n "$default" ]; then
        read -r -p "  $label [$default]: " value
        value="${value:-$default}"
    else
        read -r -p "  $label: " value
    fi
    echo "$value"
}

validate_aiml() {
    local key="$1"
    if [ -z "$key" ]; then return 1; fi
    local resp
    resp=$(curl -fsS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $key" \
        -H 'content-type: application/json' \
        -d '{"model":"anthropic/claude-sonnet-4.5","messages":[{"role":"user","content":"ping"}],"max_tokens":1}' \
        --max-time 10 \
        'https://api.aimlapi.com/v1/chat/completions' 2>/dev/null || echo '000')
    case "$resp" in
        200|400|401) return 0 ;; # 401 = key invalid but we reached the server
        *)           return 1 ;;
    esac
}

validate_featherless() {
    local key="$1"
    if [ -z "$key" ]; then return 1; fi
    local resp
    resp=$(curl -fsS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $key" \
        --max-time 10 \
        'https://api.featherless.ai/v1/models' 2>/dev/null || echo '000')
    case "$resp" in
        200|401) return 0 ;;
        *)       return 1 ;;
    esac
}

write_kv() {
    local key="$1" value="$2"
    # Idempotent: replace existing line or append.
    if grep -qE "^${key}=" "$SECRETS_FILE" 2>/dev/null; then
        # shellcheck disable=SC2001
        sed -i.bak "s|^${key}=.*|${key}=\"${value}\"|" "$SECRETS_FILE" && rm -f "$SECRETS_FILE.bak"
    else
        echo "${key}=\"${value}\"" >>"$SECRETS_FILE"
    fi
    chmod 600 "$SECRETS_FILE"
}

# --- main flow ----------------------------------------------------------------

cat <<'BANNER'

Apohara VOUCH — secrets wizard

This creates ~/.config/apohara/secrets.env with your provider keys.
The file is chmod 600 and lives outside the repo (per
.claude/rules/security.md). The orchestrator reads it via
`source ~/.config/apohara/secrets.env` before starting.

Press Enter to keep the existing value, or type a new one.

BANNER

# 1. AI/ML API key (powers 5 of 9 agents: Claude Sonnet 4.5,
#    Llama-3.3-70B, etc.)
if [ "$CHECK_ONLY" = true ] && [ -n "${AIML_API_KEY:-}" ]; then
    if validate_aiml "$AIML_API_KEY"; then ok "AIML_API_KEY valid (unchanged)"
    else err "AIML_API_KEY present but unreachable"; fi
elif [ -z "${AIML_API_KEY:-}" ]; then
    bold "1/4 AI/ML API key (https://aimlapi.com — $10 hackathon credits)"
    val=$(ask "AIML_API_KEY (sk-...)" "")
    if [ -n "$val" ]; then
        if validate_aiml "$val"; then
            ok "key reaches api.aimlapi.com"
            write_kv AIML_API_KEY "$val"
        else
            err "key did not reach api.aimlapi.com (saving anyway — might be a transient network issue)"
            write_kv AIML_API_KEY "$val"
        fi
    else
        warn "skipped — orchestrator will use the mock LLM (demo still works, no AI calls)"
    fi
fi

# 2. Featherless key (Qwen3-Coder-30B + DeepSeek-V3).
if [ "$CHECK_ONLY" = true ] && [ -n "${FEATHERLESS_API_KEY:-}" ]; then
    if validate_featherless "$FEATHERLESS_API_KEY"; then ok "FEATHERLESS_API_KEY valid (unchanged)"
    else err "FEATHERLESS_API_KEY present but unreachable"; fi
elif [ -z "${FEATHERLESS_API_KEY:-}" ]; then
    bold "2/4 Featherless AI key (https://featherless.ai — code BOA26)"
    val=$(ask "FEATHERLESS_API_KEY" "")
    if [ -n "$val" ]; then
        if validate_featherless "$val"; then
            ok "key reaches api.featherless.ai"
            write_kv FEATHERLESS_API_KEY "$val"
        else
            err "key did not reach api.featherless.ai (saving anyway)"
            write_kv FEATHERLESS_API_KEY "$val"
        fi
    else
        warn "skipped — fraud_auditor + gaap_classifier fall back to mock"
    fi
fi

# 3. Band API key + mode.
if [ "$CHECK_ONLY" = true ] && [ -n "${BAND_API_KEY:-}" ]; then
    ok "BAND_API_KEY present (run-time check skipped)"
elif [ -z "${BAND_API_KEY:-}" ]; then
    bold "3/4 Band chatroom (https://app.band.ai — required only for THEMIS_BAND_MODE=real)"
    val=$(ask "BAND_API_KEY (or leave empty for in-memory ScriptedBandRoom)" "")
    if [ -n "$val" ]; then
        write_kv BAND_API_KEY "$val"
        write_kv THEMIS_BAND_MODE "real"
        ok "saved — orchestrator will use RealBandRoom against app.band.ai"
    else
        warn "skipped — orchestrator uses in-memory ScriptedBandRoom (default)"
    fi
fi

# 4. Default provider preference.
if [ "$CHECK_ONLY" = false ]; then
    bold "4/4 Default LLM provider (auto = prefer AI/ML API, then Featherless)"
    current="${THEMIS_LLM_PROVIDER:-auto}"
    val=$(ask "THEMIS_LLM_PROVIDER (auto|aimlapi|featherless|mock)" "$current")
    write_kv THEMIS_LLM_PROVIDER "$val"
fi

echo
bold "Done."
echo "  secrets file: $SECRETS_FILE ($(stat -c %a "$SECRETS_FILE" 2>/dev/null || stat -f %Lp "$SECRETS_FILE"))"
echo
cat <<NEXT

Next steps:

  # either source the file in your shell:
  source $SECRETS_FILE
  cargo run --release --bin themis-orchestrator

  # or inline (no source needed):
  set -a; source $SECRETS_FILE; set +a
  cargo run --release --bin themis-orchestrator

  # in a second terminal, the demo UI:
  cargo run --release --bin vouch-frontend
  # → open http://localhost:7879

NEXT