#!/bin/bash
# sandbox-run.sh: run one command under a macOS Seatbelt profile (sandbox-exec) when processing
# untrusted content.
#
# WHY: the PreToolUse hooks match patterns in command strings, and shell is Turing-complete, so they
# can be bypassed. This adds an OS-enforced layer on top of them; it does not replace them.
#
# WHAT THE PROFILE BELOW DOES: (allow default), then
#   • deny network*    : all network access, loopback included, for the command and its children.
#   • deny file-read*  : $HOME/.ssh, $HOME/.gnupg, $HOME/.aws, $HOME/.claude/.credentials*, and any
#                        path matching (refresh|access).?token, /id_(rsa|dsa|ecdsa|ed25519), \.pem$,
#                        client_secret, GOCSPX, BOT_TOKEN, site-pw, oauth token or gog_credentials.
#   • deny file-write* : $HOME/.ssh, $HOME/.claude, and paths matching (refresh|access).?token.
# Everything else is allowed, including other reads and writes (shell startup files, for example),
# process execution and IPC. Environment variables pass through unchanged. Rules are built from
# $HOME as given and Seatbelt matches resolved paths, so a $HOME containing a symlink (for example
# under /tmp) leaves the subpath rules unmatched. This narrows exfiltration paths; it is not a
# complete containment boundary.
#
# REQUIRES macOS /usr/bin/sandbox-exec (marked deprecated by Apple, still shipped). If sandbox-exec
# is missing or the profile fails to load, the script exits 3 and does not run the command.
#
# TESTING: not covered by `make test` (CI runs on Linux; the PDF-screen test replaces this script
# with a stub). Checked manually on macOS (Darwin 25.6, 2026-09-28) with a temporary $HOME: reads
# under .ssh and .gnupg, reads of token- and key-named files, writes under .ssh and .claude, and a
# loopback TCP connect were refused; an ordinary read succeeded; missing sandbox-exec gave exit 3.
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

# Seatbelt profile: allow-default, then deny network and the listed secret/config paths. The kernel
# enforces these rules for the sandboxed process and its children; anything not listed is allowed.
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
  (regex #"/id_(rsa|dsa|ecdsa|ed25519)")
  (regex #"(client_secret|GOCSPX|BOT_TOKEN|site-pw|oauth[-_]?token|gog_credentials)")
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
