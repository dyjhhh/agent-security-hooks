#!/bin/bash
# Regression tests for the deny hook and the two write guards.
#
# Every hook reads a synthetic PreToolUse payload on stdin. No command in this file is executed:
# the deny hook only inspects the command string. Protected roots, recovery state, per-session
# markers and HOME all point into one temporary directory that is removed on exit.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DENY_HOOK="$ROOT/security/hook-security-deny.sh"
WRITE_HOOK="$ROOT/security/hook-protected-write-guard.sh"
APPEND_HOOK="$ROOT/security/hook-md-append-guard.sh"

command -v jq >/dev/null 2>&1 || { echo "jq is required for the guard tests"; exit 1; }

T="$(mktemp -d "${TMPDIR:-/tmp}/guard-regressions.XXXXXX")" || exit 1
trap 'rm -rf "$T"' EXIT
T="$(cd "$T" && pwd -P)"

PROTECTED="$T/protected"
STATE="$T/state"
FAKE_HOME="$T/home"
REPO="$T/repo"
mkdir -p "$PROTECTED" "$STATE" "$FAKE_HOME" "$REPO" "$T/markers" "$T/scratch"
printf '0123456789abcdef%.0s' $(seq 1 128) > "$PROTECTED/large.md"
printf 'original-uncommitted-content\n' > "$PROTECTED/live.md"

export HOME="$FAKE_HOME"
export AGENT_GUARD_PROTECTED_ROOTS="$PROTECTED:$STATE"
export AGENT_GUARD_STATE_ROOT="$STATE"
export SECURITY_DENY_LOG=/dev/null
export MD_APPEND_GUARD_STATE_DIR="$T/markers"

passed=0
failed=0
pass() { echo "  ok: $1"; passed=$((passed + 1)); }
fail() { echo "  FAIL: $1"; failed=$((failed + 1)); }

test_bash() { # name, cwd, command, expected exit
  local got
  jq -cn --arg cwd "$2" --arg cmd "$3" \
    '{tool_name:"Bash",cwd:$cwd,tool_input:{command:$cmd}}' | bash "$DENY_HOOK" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$4" ]; then pass "$1"; else fail "$1 (exit $got, want $4)"; fi
}

test_write() { # name, payload JSON, expected exit
  local got
  printf '%s' "$2" | bash "$WRITE_HOOK" >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$3" ]; then pass "$1"; else fail "$1 (exit $got, want $3)"; fi
}

echo "deny hook"
test_bash "protected rm -> deny" "$T" "rm '$PROTECTED/live.md'" 2
test_bash "relative rm with a protected cwd -> deny" "$PROTECTED" "rm live.md" 2
test_bash "protected mv away -> deny" "$T" "mv '$PROTECTED/live.md' '$T/scratch/live.md'" 2
test_bash "protected find -delete -> deny" "$T" "find '$PROTECTED' -name '*.md' -delete" 2
test_bash "protected truncate -> deny" "$T" "truncate -s 0 '$PROTECTED/live.md'" 2
test_bash "protected python os.remove -> deny" "$T" "python3 -c \"import os; os.remove('$PROTECTED/live.md')\"" 2
test_bash 'literal $HOME/Documents delete -> deny' "$T" 'rm "$HOME/Documents/probe.md"' 2
test_bash 'literal ~/Desktop delete -> deny' "$T" 'rm ~/Desktop/probe.md' 2
test_bash "git reset --hard -> deny" "$REPO" "git reset --hard HEAD" 2
test_bash "git worktree remove --force -> deny" "$T" "git worktree remove --force '$T/other-worktree'" 2
test_bash 'unguarded variable recursive delete -> deny' "$T" 'rm -rf "$TARGET"/*' 2
test_bash "killing the agent runtime -> deny" "$T" "pkill -f agent-runtime" 2
test_bash "git clean dry run -> allow" "$REPO" "git clean -nd" 0
test_bash "git restore --staged -> allow" "$REPO" "git restore --staged notes/example.md" 0
test_bash "unprotected scratch cleanup -> allow" "$T" "rm '$T/scratch/unrelated.txt'" 0
test_bash "git status -> allow" "$REPO" "git status --short" 0

echo "protected-write guard"
EDIT_PAYLOAD=$(jq -cn --arg p "$PROTECTED/live.md" --arg cwd "$T" \
  '{session_id:"test",tool_name:"Edit",cwd:$cwd,tool_input:{file_path:$p,old_string:"original",new_string:"updated"}}')
test_write "focused Edit -> snapshot and allow" "$EDIT_PAYLOAD" 0
BACKUP=$(find "$STATE/backups" -type f -name '*live.md' 2>/dev/null | head -1)
if [ -n "$BACKUP" ] && cmp -s "$BACKUP" "$PROTECTED/live.md"; then
  pass "pre-image snapshot matches the file byte for byte"
else
  fail "pre-image snapshot missing or different"
fi

SHRINK_PAYLOAD=$(jq -cn --arg p "$PROTECTED/large.md" --arg cwd "$T" \
  '{session_id:"test",tool_name:"Write",cwd:$cwd,tool_input:{file_path:$p,content:"tiny"}}')
test_write "Write shrinking a 2 KB file below half -> deny" "$SHRINK_PAYLOAD" 2

SAME_CONTENT=$(cat "$PROTECTED/large.md")
SAME_PAYLOAD=$(jq -cn --arg p "$PROTECTED/large.md" --arg c "$SAME_CONTENT" --arg cwd "$T" \
  '{session_id:"test",tool_name:"Write",cwd:$cwd,tool_input:{file_path:$p,content:$c}}')
test_write "same-size Write -> snapshot and allow" "$SAME_PAYLOAD" 0

if [ -s "$STATE/recovery-manifest.jsonl" ] \
  && jq -e 'select((.path and .backup and .sha256 and .session_id) | not)' "$STATE/recovery-manifest.jsonl" >/dev/null 2>&1; then
  fail "recovery manifest has a record without path, backup, sha256 and session_id"
elif [ "$(wc -l < "$STATE/recovery-manifest.jsonl" 2>/dev/null | tr -d ' ')" = "3" ]; then
  pass "recovery manifest has one complete record per snapshot"
else
  fail "recovery manifest missing or wrong record count"
fi

echo "append guard"
mkdir -p "$FAKE_HOME/agent-os/memory"
for i in $(seq 1 40); do printf 'line-%s\n' "$i"; done > "$FAKE_HOME/agent-os/memory/notes.md"
APPEND_PAYLOAD=$(jq -cn '{session_id:"s1",tool_name:"Bash",tool_input:{command:"echo update >> notes.md"}}')
first=$(printf '%s' "$APPEND_PAYLOAD" | bash "$APPEND_HOOK" 2>/dev/null)
if printf '%s' "$first" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1 \
  && printf '%s' "$first" | jq -r '.hookSpecificOutput.permissionDecisionReason' | grep -q 'line-40'; then
  pass "first append in a session -> deny with the file's current tail"
else
  fail "first append in a session was not denied with the tail"
fi
second=$(printf '%s' "$APPEND_PAYLOAD" | bash "$APPEND_HOOK" 2>/dev/null)
if [ -z "$second" ]; then
  pass "second append to the same file in the same session -> allow"
else
  fail "second append was blocked again"
fi

echo
echo "Results: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
