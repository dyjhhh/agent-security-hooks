#!/bin/bash
export PATH="/opt/homebrew/bin:/usr/bin:/bin:$PATH"
# hook-md-append-guard.sh — PreToolUse(Bash) READ-BEFORE-APPEND guard for canonical .md files.
# Built 2026-07-31 by Forge, at the operator's explicit request, as the STRUCTURAL fix for a real failure.
#
# ── THE FAILURE THIS EXISTS TO PREVENT ────────────────────────────────────────
# In one long session Forge appended to topic-B.md 8 times (hundreds of lines) and NEVER ONCE read
# it. Root cause: `cat >>` is cheap, reading a 1400-line file is expensive → the agent silently
# treats canonical as a WRITE-ONLY LOG and uses the conversation as its working memory. The
# conversation gets compacted; the file's precise facts (a key date, a long note from an earlier
# meeting, a caveat about which measurements to trust) never enter working memory at all. The agent
# then fills those gaps by REASONING instead of by READING, and ships confident wrong answers.
# Observed damage in that session: day counts off by one (which shifts any day-indexed threshold),
# a fabricated scheduling conflict taken from a superseded mid-file plan, and "this is new
# information" about a contact already documented at length.
#
# ── THE FIX ───────────────────────────────────────────────────────────────────
# FIRST append to a given canonical .md IN A GIVEN SESSION → DENY once, and hand back that file's
# tail so the agent physically cannot write without seeing current state. Subsequent appends to the
# SAME file in the SAME session → pass through silently (the read already happened).
# Cost: one extra round-trip per file per session. That is the whole price.
#
# Scope: ONLY Bash `>>` appends. Write/Edit/MultiEdit already force a prior Read at the tool layer,
# so they need no guard here.
#
# 🛟 FAIL-OPEN (the operator's #1 rule = never break real work): any parse problem, missing jq, unknown
# file, or unexpected state → exit 0 → the command runs untouched.

INPUT=$(cat 2>/dev/null) || exit 0
command -v jq >/dev/null 2>&1 || exit 0

CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[ -z "$CMD" ] && exit 0

# Only care about append redirection. `>` (truncate) is handled by hook-protected-write-guard.sh.
printf '%s' "$CMD" | grep -q '>>' || exit 0

SESSION=$(printf '%s' "$INPUT" | jq -r '.session_id // "nosess"' 2>/dev/null)
[ -z "$SESSION" ] && SESSION="nosess"

# Canonical roots. A bare filename in the command is resolved against these, so the guard works
# whether the agent used an absolute path, a relative path, or `cd`-ed into the directory first.
ROOTS="$HOME/.claude/projects/-project/memory $HOME/agent-os/memory $HOME/agent-os/agent-os/memory"

# Collect .md basenames mentioned anywhere in the command (cheap + path-resolution-free).
NAMES=$(printf '%s' "$CMD" | grep -oE '[A-Za-z0-9][A-Za-z0-9._-]*\.md' 2>/dev/null | sort -u)
[ -z "$NAMES" ] && exit 0

# Per-session markers. The override exists so tests can keep them inside a temporary directory.
MARKER_DIR="${MD_APPEND_GUARD_STATE_DIR:-/tmp}"

UNREAD=""
for name in $NAMES; do
  for dir in $ROOTS; do
    f="$dir/$name"
    [ -f "$f" ] || continue
    key=$(printf '%s' "$f" | shasum 2>/dev/null | cut -c1-12)
    [ -z "$key" ] && continue
    marker="$MARKER_DIR/.md-append-guard-${SESSION}-${key}"
    if [ ! -f "$marker" ]; then
      touch "$marker" 2>/dev/null
      UNREAD="$UNREAD|$f"
    fi
    break   # first root that has this basename wins
  done
done

[ -z "$UNREAD" ] && exit 0

# Build the denial reason: current tail of each first-touch file.
REASON="🔒 READ-BEFORE-APPEND GUARD — first append to this canonical file in this session.

WHY: appending without reading is how stale mid-file plans get quoted as current, how day/date
counters drift, and how already-documented facts get announced as 'new'. Below is the CURRENT tail
of each file. Read it, reconcile your intended write against it, then re-issue the same command —
it will go through unblocked this time (per file, per session).

CHECK BEFORE YOU RE-ISSUE:
  1. Does the tail already contain what you were about to write? (then don't duplicate it)
  2. Does the tail CONTRADICT it? (the tail is newer — .md files are append-ordered, later = newer)
  3. Any date / day-count / quantity / amount in your write: did it come from THIS FILE, or from the
     conversation? Conversation-sourced numbers are the ones that drift. Re-derive from the file.
"

IFS='|'
for f in $UNREAD; do
  [ -z "$f" ] && continue
  total=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
  REASON="$REASON
──────── $f  (total ${total} lines · showing last 35) ────────
$(tail -35 "$f" 2>/dev/null)
"
done
unset IFS

jq -nc --arg r "$REASON" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: $r
  }
}' 2>/dev/null || exit 0

exit 0
