#!/bin/bash
export PATH="/opt/homebrew/bin:/usr/bin:/bin:$PATH"
# hook-md-append-guard.sh — PreToolUse(Bash) READ-BEFORE-APPEND guard for canonical .md files.
# Built 2026-07-31 by Forge, at the operator's explicit request, as the STRUCTURAL fix for a real failure.
# Direction-aware since 2026-10-24, after a second failure (see WHICH END IS NEWEST).
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
# FIRST `>>` append to a given canonical .md IN A GIVEN SESSION → DENY once, and hand back that file's
# newest region, so the retry comes after the current state was shown to the agent. Subsequent appends to the
# SAME file in the SAME session → pass through silently. Other write paths (`>`, tee, python, a
# basename not under ROOTS) and any parse failure are not covered; see FAIL-OPEN below.
# Cost: one extra round-trip per file per session. That is the whole price.
#
# ── WHICH END IS NEWEST (2026-10-24) ──────────────────────────────────────────
# The first version always returned the last 35 lines and said "later = newer". Many canonical files
# are newest-first, so for them it returned the OLDEST region as current. An agent then answered from
# the tail of such a file and reported an entry weeks old as the latest, while the newer ones sat at
# the top. Each file now declares its order: `order: newest-first | append | mixed` as a frontmatter
# key, or `<!-- order: ... -->` on line 1. newest-first → first 35 lines after the frontmatter, and
# "insert at the head"; append → last 35 lines; mixed → first 20 and last 20, and "compare dates".
# No marker → a guess from dated `## YYYY-MM-DD` headings, and the denial SAYS it is a guess.
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

# Only care about append redirection. Shell `>` truncation is not checked here or by
# hook-protected-write-guard.sh, which sees Write/Edit tool calls only.
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

# One awk pass per file → "<order> <lines-to-skip> <marker|guess>". A frontmatter `order:` key or a
# line-1 comment wins; otherwise the position of the newest dated heading decides.
probe_order() {
  awk '
    NR == 1 && /^---[[:space:]]*$/ { infm = 1; next }
    NR == 1 && match($0, /<!--[[:space:]]*order:[[:space:]]*[a-z-]+[[:space:]]*-->/) {
      v = substr($0, RSTART, RLENGTH); gsub(/<!--[[:space:]]*order:[[:space:]]*|[[:space:]]*-->/, "", v)
      mk = v; skip = 1
    }
    infm == 1 {
      if ($0 ~ /^---[[:space:]]*$/) { infm = 2; skip = NR; mk = fm }
      else if (NR > 30) infm = 0
      else if ($0 ~ /^order:[[:space:]]*[a-z-]+[[:space:]]*$/) { fm = $0; sub(/^order:[[:space:]]*/, "", fm); sub(/[[:space:]]+$/, "", fm) }
    }
    /^#+[ \t]+[^A-Za-z0-9]*20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]/ {
      match($0, /20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]/); d = substr($0, RSTART, RLENGTH)
      if (++n == 1) first = d
      if (d > max) max = d
      last = d
    }
    END {
      if (mk == "newest-first" || mk == "append" || mk == "mixed") { print mk, skip + 0, "marker"; exit }
      h = (n < 2 || last == max) ? "append" : (first == max) ? "newest-first" : "mixed"
      print h, skip + 0, "guess"
    }' "$1" 2>/dev/null
}

# Build the denial reason: the newest region of each first-touch file.
REASON="🔒 READ-BEFORE-APPEND GUARD — first append to this canonical file in this session.

WHY: appending without reading is how stale mid-file plans get quoted as current, how day/date
counters drift, and how already-documented facts get announced as 'new'. Below is the NEWEST region
of each file; which end that is comes from the file's order. Read it, reconcile your intended write
against it, then re-issue the same command; it will go through unblocked this time (per file, per
session). For a newest-first file, insert at the head instead of re-issuing the append.

CHECK BEFORE YOU RE-ISSUE:
  1. Does the excerpt already contain what you were about to write? (then don't duplicate it)
  2. Does the excerpt CONTRADICT it? (the excerpt is the newest region; never assume tail = newer)
  3. Any date / day-count / quantity / amount in your write: did it come from THIS FILE, or from the
     conversation? Conversation-sourced numbers are the ones that drift. Re-derive from the file.
"

IFS='|'
for f in $UNREAD; do
  [ -z "$f" ] && continue
  total=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
  IFS=' ' read -r order skip src <<PROBE
$(probe_order "$f")
PROBE
  case $skip in ''|*[!0-9]*) skip=0 ;; esac
  case "$order" in
    newest-first)
      excerpt=$(sed -n "$((skip + 1)),$((skip + 35))p" "$f" 2>/dev/null)
      label="order: newest-first · first 35 lines after the frontmatter · insert new entries at the head" ;;
    mixed)
      excerpt="$(sed -n "$((skip + 1)),$((skip + 20))p" "$f" 2>/dev/null)
⋯
$(tail -20 "$f" 2>/dev/null)"
      label="order: mixed · first 20 and last 20 lines · compare the dates before trusting either end" ;;
    *)
      excerpt=$(tail -35 "$f" 2>/dev/null)
      label="order: append · last 35 lines" ;;
  esac
  [ "$src" = "marker" ] || label="$label · NO order MARKER: direction inferred from dated headings"
  REASON="$REASON
──────── $f  (total ${total} lines · ${label}) ────────
$excerpt
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
