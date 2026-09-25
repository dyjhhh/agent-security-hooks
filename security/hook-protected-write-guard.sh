#!/bin/bash
# hook-protected-write-guard.sh — PreToolUse guard for Write/Edit/MultiEdit.
#
# For canonical files this hook:
#   1. snapshots the exact pre-image outside the repo before every edit;
#   2. blocks a single operation that would catastrophically shrink an existing file;
#   3. writes an append-only recovery manifest.
#
# It does not decide whether content is correct. Git remains the durable history layer.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
set -u

INPUT=$(cat)
command -v jq >/dev/null 2>&1 || {
  echo "🛑 Protected-write guard cannot run because jq is unavailable." >&2
  exit 2
}

TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null) || exit 2
FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 2
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null) || exit 2
[ -z "$FILE_PATH" ] && exit 0
[ -z "$CWD" ] && CWD=$(pwd -P)

case "$FILE_PATH" in
  "~/"*) FILE_PATH="$HOME/${FILE_PATH#\~/}" ;;
  /*) ;;
  *) FILE_PATH="$CWD/$FILE_PATH" ;;
esac

# Resolve symlink aliases such as agent-os/memory. New files are resolved through their parent.
if [ -e "$FILE_PATH" ]; then
  RESOLVED=$(/bin/realpath "$FILE_PATH" 2>/dev/null || printf '%s' "$FILE_PATH")
else
  PARENT=$(dirname "$FILE_PATH")
  BASE=$(basename "$FILE_PATH")
  if [ -d "$PARENT" ]; then
    PARENT=$(/bin/realpath "$PARENT" 2>/dev/null || printf '%s' "$PARENT")
  fi
  RESOLVED="$PARENT/$BASE"
fi

STATE_ROOT="${AGENT_GUARD_STATE_ROOT:-$HOME/.local/state/operator-agent-guard}"
PROTECTED_ROOTS="${AGENT_GUARD_PROTECTED_ROOTS:-$HOME/agent-os/memory:$HOME/context-portfolio:$HOME/Personal:$HOME/.claude/settings.json:$HOME/agent-os/.claude/settings.json:$HOME/agent-os/security/hook-security-deny.sh:$HOME/agent-os/security/hook-protected-write-guard.sh}"
IS_PROTECTED=0
OLD_IFS=$IFS
IFS=:
for ROOT in $PROTECTED_ROOTS; do
  [ -z "$ROOT" ] && continue
  if [ -e "$ROOT" ]; then
    ROOT=$(/bin/realpath "$ROOT" 2>/dev/null || printf '%s' "$ROOT")
  fi
  case "$RESOLVED" in
    "$ROOT"|"$ROOT"/*) IS_PROTECTED=1; break ;;
  esac
done
IFS=$OLD_IFS
[ "$IS_PROTECTED" -eq 0 ] && exit 0

BACKUP_ROOT="$STATE_ROOT/backups"
MANIFEST="$STATE_ROOT/recovery-manifest.jsonl"
mkdir -p "$BACKUP_ROOT" || {
  echo "🛑 Cannot create canonical recovery store at $BACKUP_ROOT." >&2
  exit 2
}
chmod 700 "$STATE_ROOT" "$BACKUP_ROOT" 2>/dev/null || true

if [ -f "$RESOLVED" ]; then
  TS=$(date -u '+%Y%m%dT%H%M%S')
  SAFE_PATH=$(printf '%s' "$RESOLVED" | sed 's#^/##; s#/#__#g')
  BACKUP="$BACKUP_ROOT/${TS}-$$-${SAFE_PATH}"
  cp -p "$RESOLVED" "$BACKUP" || {
    echo "🛑 Refusing canonical edit because the pre-write snapshot failed: $RESOLVED" >&2
    exit 2
  }
  chmod 600 "$BACKUP" 2>/dev/null || true
  SHA=$(/usr/bin/shasum -a 256 "$BACKUP" | awk '{print $1}')
  SESSION=$(printf '%s' "$INPUT" | jq -r '.session_id // "unknown"')
  jq -cn --arg ts "$TS" --arg tool "$TOOL" --arg path "$RESOLVED" \
    --arg backup "$BACKUP" --arg sha256 "$SHA" --arg session "$SESSION" \
    '{timestamp:$ts,tool:$tool,path:$path,backup:$backup,sha256:$sha256,session_id:$session}' \
    >> "$MANIFEST" || {
      echo "🛑 Refusing canonical edit because the recovery manifest could not be written." >&2
      exit 2
    }

  CURRENT_SIZE=$(wc -c < "$RESOLVED" | tr -d ' ')
  NEW_SIZE=$CURRENT_SIZE
  case "$TOOL" in
    Write)
      NEW_SIZE=$(printf '%s' "$INPUT" | jq -j '.tool_input.content // ""' | wc -c | tr -d ' ')
      ;;
    Edit)
      OLD_SIZE=$(printf '%s' "$INPUT" | jq -j '.tool_input.old_string // ""' | wc -c | tr -d ' ')
      REPLACEMENT_SIZE=$(printf '%s' "$INPUT" | jq -j '.tool_input.new_string // ""' | wc -c | tr -d ' ')
      if [ "$OLD_SIZE" -le "$CURRENT_SIZE" ]; then
        NEW_SIZE=$((CURRENT_SIZE - OLD_SIZE + REPLACEMENT_SIZE))
      fi
      ;;
  esac

  # A normal focused edit cannot erase over half of a nontrivial canonical file at once.
  # Intentional rewrites should be decomposed, reviewed, or performed manually by the operator.
  if [ "$CURRENT_SIZE" -ge 1024 ] && [ "$NEW_SIZE" -lt $((CURRENT_SIZE / 2)) ]; then
    echo "🛑 BLOCKED catastrophic canonical shrink: $RESOLVED would go from ${CURRENT_SIZE}B to approximately ${NEW_SIZE}B. Pre-image saved at $BACKUP. Use a focused Edit or ask the operator to perform an intentional replacement manually." >&2
    exit 2
  fi
fi

# Keep 30 days of local pre-images. This cleanup only touches the dedicated recovery store.
find "$BACKUP_ROOT" -type f -mtime +30 -delete 2>/dev/null || true
exit 0
