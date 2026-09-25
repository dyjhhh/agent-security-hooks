#!/bin/bash
# sandbox-run.sh — OS-LEVEL CONTAINMENT death-line for UNTRUSTED-CONTENT processing (agent-OS #4).
#
# DOCTRINE (Hermes SECURITY.md, adapted): against an adversarial LLM / injected content, the ONLY real
# security boundary is the OS kernel. approval prompts, denylist regexes, and our 9-layer PreToolUse
# hook are review AIDS that raise the bar — but shell is Turing-complete, so a denylist is structurally
# incomplete = NOT containment. This wraps a command in a kernel-enforced macOS Seatbelt sandbox so the
# two death-line threats are IMPOSSIBLE, not just discouraged:
#   • NO network  → data physically cannot be exfiltrated (nowhere to send it). This is the PRIMARY
#                   containment: whatever untrusted content is read, it can't leave the box.
#   • NO secret reads → ~/.ssh keys, refresh/access tokens, credentials, .pem — kernel-blocked, so a
#                   compromised processor can't steal creds for lateral movement.
#   • NO secret/config writes → can't tamper with ~/.ssh or ~/.claude.
# Everything else (dyld, system libs, the input file, temp/output) works normally, so legit tools
# (pdftotext, python text analysis) run unchanged. LAYERS ON TOP of the hook — does not replace it.
#
# FAIL-CLOSED: if the sandbox can't be established, the command does NOT run (containment is the point).
# Usage:  sandbox-run.sh <command> [args...]
#   e.g.  sandbox-run.sh pdftotext /path/untrusted.pdf /path/out.txt
#         sandbox-run.sh python3 analyze_untrusted.py
set -uo pipefail
[ "$#" -ge 1 ] || { echo "usage: sandbox-run.sh <command> [args...]" >&2; exit 2; }

command -v sandbox-exec >/dev/null 2>&1 || {
  echo "🛑 sandbox-run: sandbox-exec unavailable — REFUSING to run uncontained (fail-closed)." >&2; exit 3; }

H="$HOME"
SBX=$(/usr/bin/mktemp "${TMPDIR:-/tmp}/sbx-profile.XXXXXX") || exit 3
mv "$SBX" "$SBX.sb"; SBX="$SBX.sb"
trap 'rm -f "$SBX"' EXIT

# Seatbelt profile. allow-default + deny the death-line vectors (network + secret read/write). Kernel
# enforces these regardless of what the sandboxed process tries.
cat > "$SBX" <<EOF
(version 1)
(allow default)
(deny network*)
(deny file-read*
  (subpath "$H/.ssh")
  (subpath "$H/.gnupg")
  (subpath "$H/.aws")
  (regex #"^$H/\\.claude/\\.credentials")
  (regex #"(refresh|access).?token")
  (regex #"/id_(rsa|dsa|ecdsa|ed25519|macmini)")
  (regex #"(client_secret|GOCSPX|BOT_TOKEN|compass-pw|atlas_oauth|gog_credentials)")
  (regex #"\\.pem\$")
)
(deny file-write*
  (subpath "$H/.ssh")
  (subpath "$H/.claude")
  (regex #"(refresh|access).?token")
)
EOF

# fail-closed: profile must parse (dry compile via a trivial no-op under it)
if ! /usr/bin/sandbox-exec -f "$SBX" /usr/bin/true 2>/dev/null; then
  echo "🛑 sandbox-run: Seatbelt profile failed to load — REFUSING to run uncontained (fail-closed)." >&2
  exit 3
fi

/usr/bin/sandbox-exec -f "$SBX" "$@" && rc=0 || rc=$?
exit $rc
