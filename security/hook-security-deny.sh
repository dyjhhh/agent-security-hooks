#!/bin/bash
export PATH="/opt/homebrew/bin:/usr/bin:/bin:$PATH"
# hook-security-deny.sh — PreToolUse Bash guard (prompt-injection / exfil defense).
# Blocks genuinely-never-legit operations plus destructive commands aimed at the operator's
# canonical brain, context portfolio, or recovery store. Ordinary edits still pass.
# FAIL-OPEN on parse error (never break real work). Fast: pure grep, jq for extraction.
INPUT=$(cat)
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$CMD" ] && exit 0
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null)
[ -z "$CWD" ] && CWD=$(pwd -P)
LOG="${SECURITY_DENY_LOG:-$HOME/agent-os/logs/security-deny.log}"
deny(){ mkdir -p "$(dirname "$LOG")" 2>/dev/null; echo "$(date -Iseconds) DENIED [$1]: $CMD" >>"$LOG"
  echo "🛑 BLOCKED by security guard ($1): matches an exfiltration/destructive pattern never used in legit work. If you (the real user) truly intend this, run it yourself in a terminal." >&2; exit 2; }

# Default protected roots. Setting the colon-separated AGENT_GUARD_PROTECTED_ROOTS replaces this list;
# the tests point it at temporary directories.
# Private deployments pass their full list, including site-specific roots, through AGENT_GUARD_PROTECTED_ROOTS.
PROTECTED_ROOTS="${AGENT_GUARD_PROTECTED_ROOTS:-$HOME/agent-os/memory:~/agent-os/memory:$HOME/.claude/projects/-project/memory:$HOME/context-portfolio:$HOME/Personal:$HOME/Documents:$HOME/Desktop:$HOME/.local/state/operator-agent-guard:$HOME/.claude/settings.json:$HOME/agent-os/.claude/settings.json:$HOME/agent-os/security/hook-security-deny.sh:$HOME/agent-os/security/hook-protected-write-guard.sh}"

references_protected_path() {
  local old_ifs root
  old_ifs=$IFS
  IFS=:
  for root in $PROTECTED_ROOTS; do
    [ -z "$root" ] && continue
    case "$CWD" in
      "$root"|"$root"/*) IFS=$old_ifs; return 0 ;;
    esac
    printf '%s' "$CMD" | grep -Fq "$root" && { IFS=$old_ifs; return 0; }
  done
  IFS=$old_ifs

  # Literal aliases are checked before shell expansion. Relative paths matter when the
  # hook cwd is the agent-os repo or when the command explicitly cd's there.
  printf '%s' "$CMD" | grep -qE '(~/|\$HOME/)(agent-os/(agent-os/)?memory|agent-os/memory|\.claude/projects/-project/memory|context-portfolio|Personal|Documents|Desktop|\.local/state/operator-agent-guard|\.claude/settings\.json)(/|[[:space:]"'"'"']|$)' \
    && return 0
  case "$CWD" in
    "$HOME/agent-os"|"$HOME/agent-os"/*)
      printf '%s' "$CMD" | grep -qE '(^|[[:space:]"'"'"'=])(memory|agent-os/memory)(/|[[:space:]"'"'"']|$)' && return 0
      ;;
  esac
  printf '%s' "$CMD" | grep -qE 'cd[[:space:]]+([^;&|]*agent-os/)?(agent-os/)?memory([/[:space:]"'"'"'];]|$)' \
    && return 0
  return 1
}

# 1. credential read embedded in / piped to network egress
echo "$CMD" | grep -qiE '(curl|wget|nc |ncat|telnet|/dev/tcp).*(\$\(|`).*(cat|grep|head|tail|base64|xxd|openssl|cut)' \
  && echo "$CMD" | grep -qiE '(id_rsa|id_ed25519|\.ssh/id|\.env|refresh.?token|access.?token|client_secret|oauth[-_]?token|gog_credentials|CLIENT_SECRET|GOCSPX|ANTHROPIC_API|github_pat|BOT_TOKEN|api_key)' \
  && deny "cred-exfil-network"
echo "$CMD" | grep -qiE '(cat|grep|base64|xxd|openssl|cut)\b.*(id_rsa|id_ed25519|\.ssh/id|\.env\b|refresh.?token|access.?token|client_secret|oauth[-_]?token|gog_credentials|CLIENT_SECRET|github_pat|BOT_TOKEN)' \
  && echo "$CMD" | grep -qiE '\|\s*(curl|wget|nc |ncat|telnet)' && deny "cred-pipe-network"

# 2. chmod loosening perms on sensitive files
echo "$CMD" | grep -qiE 'chmod\s+([0-7]?[0-7][4-7][4-7]\b|\+r\b|a\+r|o\+r|g\+r).*(\.ssh|id_rsa|id_ed25519|\.env\b|refresh.?token|client_secret|gog_credentials|oauth[-_]?token|\.gmail)' \
  && deny "chmod-loosen-secret"

# 3. git force-push (never legit in synced multi-agent setup)
echo "$CMD" | grep -qiE 'git\s+push\b.*(--force\b|--force-with-lease|[[:space:]]-f\b)' && deny "git-force-push"

# 3b. Destructive Git is manual-user-only in every repo. This directly blocks the
# force-remove/reset class of failure disclosed for GPT-5.6 Sol.
printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+(reset\b[^;&|]*--hard|checkout[[:space:]]+--|worktree[[:space:]]+remove\b|stash[[:space:]]+(drop|clear)\b|branch[[:space:]]+-D\b)' \
  && deny "git-destructive"
printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+restore\b' \
  && ! printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+restore\b[^;&|]*(--staged|-S)([[:space:]]|$)' \
  && deny "git-destructive-restore"
printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+clean\b' \
  && ! printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+clean\b[^;&|]*(--dry-run|-[a-zA-Z]*n)' \
  && deny "git-destructive-clean"

# 4. kill agent-critical daemons (disable oversight)
echo "$CMD" | grep -qiE '(pkill|killall|kill)\b.*(agent-runtime|agent-sync|auto-sync|telegram-watchdog|intelligent-heartbeat|agent-recovery|codex-bridge)' \
  && deny "kill-critical-daemon"

# 5. rm -rf of home root or system root
echo "$CMD" | grep -qiE 'rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|~|~/|\$HOME|\$HOME/|/Users/[^/ ]+)\s*(;|&&|\||$)' \
  && deny "rm-rf-home-root"
echo "$CMD" | grep -qiE 'rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+("?\$HOME"?|~|/Users/[^/ ]+)/\*' \
  && deny "rm-rf-home-contents"
echo "$CMD" | grep -qE 'rm[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*f?[[:space:]]+"?\$[A-Za-z_][A-Za-z0-9_]*"?/\*' \
  && ! echo "$CMD" | grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*:\?[^}]*\}' \
  && deny "rm-rf-unguarded-variable-contents"

# 5b. Canonical-brain deletion / relocation / destructive overwrite. These operations
# are never agent-legitimate: canonical content is archived or edited, not deleted.
if references_protected_path; then
  printf '%s' "$CMD" | grep -qiE '(^|[;&|[:space:]])(rm|rmdir|unlink|shred|srm|trash)([[:space:]]|$)' \
    && deny "protected-path-delete"
  printf '%s' "$CMD" | grep -qiE '(^|[;&|[:space:]])mv([[:space:]]|$)' \
    && deny "protected-path-relocate"
  printf '%s' "$CMD" | grep -qiE '(^|[;&|[:space:]])truncate([[:space:]]|$)|find\b[^;&|]*(-delete|-exec(dir)?[[:space:]]+(rm|unlink))|rsync\b[^;&|]*--delete' \
    && deny "protected-path-destructive-write"
  printf '%s' "$CMD" | grep -qiE '(os\.(remove|unlink)|shutil\.rmtree|\.unlink\(|fs\.(unlink|rm)(Sync)?\(|File\.(delete|unlink)|Deno\.remove)' \
    && deny "protected-path-programmatic-delete"
  printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+(rm\b|checkout[[:space:]]+--|reset\b[^;&|]*--hard)' \
    && deny "protected-path-git-destructive"
  printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+restore\b' \
    && ! printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+restore\b[^;&|]*(--staged|-S)([[:space:]]|$)' \
    && deny "protected-path-git-restore"
  printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+clean\b' \
    && ! printf '%s' "$CMD" | grep -qiE 'git[[:space:]]+clean\b[^;&|]*(--dry-run|-[a-zA-Z]*n)' \
    && deny "protected-path-git-clean"
  printf '%s' "$CMD" | grep -qiE '(chmod|chflags)[[:space:]][^;&|]*(-N|nouchg|noschg|nohidden)' \
    && deny "protected-path-protection-removal"
fi

# 6. PII (SSN / credit-card / passport / routing / account number) headed to network egress.
#    Injection tries "compile her SSN+cards and send" — this blocks the SEND step deterministically.
echo "$CMD" | grep -qiE '(curl|wget|nc |ncat|telnet|/dev/tcp|scp |rsync\s.*@|sendmail|mailx)' \
  && echo "$CMD" | grep -qiE '([0-9]{3}-[0-9]{2}-[0-9]{4}|\bSSN\b|social.?security|passport.?(no|num|number)|routing.?(no|num|number)|account.?(no|num|number)|([0-9]{4}[ -]){3}[0-9]{4})' \
  && deny "pii-exfil-network"

# 7. bulk archive/copy of the memory-brain or a secrets dir piped to network / upload sink.
#    Injection tries "back up all memory files to <url>" — legit sync is git-only, never tar|curl.
echo "$CMD" | grep -qiE '(tar|zip|gzip|cp\s+-[a-zA-Z]*r|rsync|ditto)\b.*(agent-os/memory|-project/memory|\.ssh|agent-os|/Personal|important-docs)' \
  && echo "$CMD" | grep -qiE '(\|\s*(curl|wget|nc |ncat)|scp\s|rsync\s.*@|transfer\.sh|file\.io|0x0\.st|--upload|webhook\.site|ngrok|requestbin|pastebin)' \
  && deny "bulk-brain-exfil"

# 8. uploading any local file to an external paste / transfer / webhook sink (classic exfil channel).
echo "$CMD" | grep -qiE '(curl|wget)\b' \
  && echo "$CMD" | grep -qiE '(transfer\.sh|file\.io|0x0\.st|pastebin\.com|hastebin|termbin|webhook\.site|requestbin|pipedream\.net|ngrok\.io|burpcollaborator|oast\.)' \
  && echo "$CMD" | grep -qiE '(-F\b|--form|--data|--data-binary|--upload-file|-T\b|@/|@~|@\$)' \
  && deny "file-upload-external-sink"

exit 0
