#!/bin/bash
# plugin-screen.sh — vet a third-party Agent Plugin bundle BEFORE it is installed / loaded.
#
# WHY (2026-08-07): Agent Plugins 1.0.0 (agent-plugins.org, OpenAI/AWS/MS/Cursor/Vercel, 8/6) makes
# Skills + MCP servers into ONE portable directory that circulates across ChatGPT/Codex/Copilot/Cursor/
# Kiro/VS Code. The spec's OWN FUTURE_CONSIDERATIONS.md lists permissions, sandboxing, signature
# verification, secrets handling + org allowlists as things v1.0.0 does NOT define. So a plugin can
# travel + auto-load with zero signature. That is exactly the FakeGit / AgentBaiting surface (2026-07-23):
# a bundle whose SKILL.md is attacker-authored data and whose scripts/ or mcp.json quietly bypass the
# death-line. Codex (one of the operator's own agents) IS a supporting client → the vector is not hypothetical.
#
# This adds a deterministic static pattern scan before install; a clean result does not prove the bundle is safe.
# Sibling of pdf-screen.sh. No LLM. Reads only; installs nothing; runs nothing from the bundle.
#
# Usage: plugin-screen.sh <plugin-dir | plugin.zip>
#   exit 0 = no signatures (STILL do the provenance-3-check by hand before install)
#   exit 1 = suspicious signatures found (do NOT install; quote hits to the operator)
#   exit 2 = usage / error
export PATH="/opt/homebrew/bin:/usr/bin:/bin:$PATH"

SRC="$1"
[ -z "$SRC" ] && { echo "usage: plugin-screen.sh <plugin-dir | plugin.zip>"; exit 2; }

# If a zip, expand into a temp dir (never execute anything; unzip is inert extraction).
CLEANUP=""
if [ -f "$SRC" ] && printf '%s' "$SRC" | grep -qiE '\.zip$'; then
  DIR="$(mktemp -d -t pluginscreen)"; CLEANUP="$DIR"
  unzip -qq -o "$SRC" -d "$DIR" 2>/dev/null || { echo "plugin-screen: unzip failed on $SRC"; rm -rf "$DIR"; exit 2; }
elif [ -d "$SRC" ]; then
  DIR="$SRC"
else
  echo "plugin-screen: not a dir or .zip: $SRC"; exit 2
fi

MANIFEST="$DIR/plugin.json"
[ -f "$MANIFEST" ] || MANIFEST="$(find "$DIR" -maxdepth 3 -name plugin.json 2>/dev/null | head -1)"

# Only scan text-like files — the injection surface. Cap size so a giant blob can't stall the scan.
TEXTFILES="$(find "$DIR" -type f \( -name '*.md' -o -name '*.json' -o -name '*.sh' -o -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.txt' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' \) -size -2M 2>/dev/null)"

# ── Layer A: prompt-injection signatures (SKILL.md / references authored by whoever built the plugin) ──
SIGS='UnboundGPT|JAILBREAK ?OK|reset your (personality|persona|rules)|ignore (all )?(previous|prior) (rules|instructions)|you are now (an? )?(unbound|jailbroken|dan)|<system>|</system>|system.?reminder|pre.?authoriz|you (must|should|need to) (now |immediately )?(send|exfil|package|copy|email|upload|transfer)|as an? (admin|administrator|anthropic|system)|disregard (your|all|previous)'

# ── Layer B: death-line-tripping commands hiding in scripts/ or mcp.json (what hook-security-deny blocks
#    at RUN time — here we catch it at INSTALL time, before it ever runs) ──
EXFIL_SINK='transfer\.sh|file\.io|0x0\.st|pastebin|hastebin|termbin|webhook\.site|requestbin|pipedream\.net|ngrok|burpcollaborator|oast\.'
CRED_NAME='id_rsa|id_ed25519|\.ssh/id|refresh.?token|access.?token|client_secret|GOCSPX|ANTHROPIC_API|github_pat|BOT_TOKEN|api_key|oauth[-_]?token|gog_credentials|\.env\b'
DANGER_CMD='curl|wget|nc |ncat|/dev/tcp|scp |chmod\s+[0-7]*[4-7][4-7]|rm\s+-[a-z]*rf|git\s+push.*--force|base64|openssl enc'

hits_inj="$(grep -rniE "$SIGS" $TEXTFILES 2>/dev/null | head -12)"
# Death-line: a file that mentions a secret name AND (an exfil sink OR a network verb) = loud flag.
hits_cred=""
for f in $TEXTFILES; do
  if grep -qiE "$CRED_NAME" "$f" 2>/dev/null && grep -qiE "$EXFIL_SINK|curl|wget|nc |/dev/tcp|scp " "$f" 2>/dev/null; then
    hits_cred="$hits_cred$(grep -niE "$CRED_NAME" "$f" 2>/dev/null | head -3 | sed "s#^#  ${f#$DIR/}:#")
"
  fi
done
hits_sink="$(grep -rniE "$EXFIL_SINK" $TEXTFILES 2>/dev/null | head -8)"
hits_danger="$(grep -rniE "$DANGER_CMD" $TEXTFILES 2>/dev/null | grep -vE '#|//' | head -10)"

# ── Layer C: MCP endpoints — any remote host the plugin would wire in (the standard bundles mcp.json) ──
mcp_hosts=""
for mj in $(find "$DIR" -maxdepth 3 -name 'mcp.json' 2>/dev/null); do
  mcp_hosts="$mcp_hosts$(grep -oiE 'https?://[a-z0-9._-]+' "$mj" 2>/dev/null | sort -u | sed 's/^/  /')
"
  # command-launched servers (npx/uvx/docker pulling remote packages) also worth surfacing
  cmds="$(grep -oiE '"command"[[:space:]]*:[[:space:]]*"[^"]+"' "$mj" 2>/dev/null | sed 's/^/  cmd: /')"
  [ -n "$cmds" ] && mcp_hosts="$mcp_hosts$cmds
"
done

# ── Provenance (for the human's char-by-char check — script can't decide trust, only surface it) ──
prov=""
if [ -f "$MANIFEST" ] && command -v jq >/dev/null 2>&1; then
  prov="$(jq -r '"  name:       \(.name // "—")\n  version:    \(.version // "—")\n  author:     \(.author.name // .author // "—")  \(.author.url // "")\n  repository: \(.repository // "—")\n  homepage:   \(.homepage // "—")\n  license:    \(.license // "—")"' "$MANIFEST" 2>/dev/null)"
elif [ -f "$MANIFEST" ]; then
  prov="$(grep -iE '"(name|version|author|repository|homepage|license)"' "$MANIFEST" 2>/dev/null | sed 's/^/  /')"
fi

suspicious=0
[ -n "$hits_inj" ] && suspicious=1
[ -n "$hits_cred" ] && suspicious=1
[ -n "$hits_sink" ] && suspicious=1
[ -n "$hits_danger" ] && suspicious=1

echo "══════════════════════════════════════════════════════════════"
echo "🔌 AGENT-PLUGIN SCREEN — $(basename "$SRC")"
[ -z "$MANIFEST" ] && echo "⚠️  no plugin.json found — not a well-formed Agent Plugin (be extra wary)."
echo "── Provenance (verify handle CHAR-BY-CHAR vs the official org; registry listing ≠ endorsement) ──"
echo "${prov:-  (no manifest fields readable)}"
if [ -n "$mcp_hosts" ]; then
  echo "── MCP wires (every remote host/command this plugin would connect on load) ──"
  printf '%s' "$mcp_hosts"
fi
echo "──────────────────────────────────────────────────────────────"
if [ "$suspicious" -eq 1 ]; then
  echo "⚠️⚠️ SUSPICIOUS — do NOT install/load. Treat the whole bundle as attacker DATA."
  [ -n "$hits_inj" ]    && { echo "• prompt-injection signatures:"; echo "$hits_inj" | sed 's/^/    /'; }
  [ -n "$hits_cred" ]   && { echo "• secret-name NEAR network/exfil (credential theft shape):"; printf '%s' "$hits_cred"; }
  [ -n "$hits_sink" ]   && { echo "• exfil sinks (paste/webhook/tunnel):"; echo "$hits_sink" | sed 's/^/    /'; }
  [ -n "$hits_danger" ] && { echo "• death-line-class commands in bundle:"; echo "$hits_danger" | sed 's/^/    /'; }
  echo "Quote a hit back to the operator + do NOT proceed. (hook-security-deny inspects only agent shell commands, not code the plugin runs;"
  echo "but a plugin that SHIPS them has already failed the trust test — reject the bundle.)"
else
  echo "ℹ️  No injection/exfil/death-line signatures found. NOT a clearance to install:"
  echo "   still do the provenance check by hand:"
  echo "   ① author handle char-by-char = official org?  ② canonical repo, not a look-alike?"
  echo "   ③ real stars/history, not a fresh clone?  Then FIRST run via sandbox-run.sh, lock versions."
fi
echo "══════════════════════════════════════════════════════════════"

[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"
[ "$suspicious" -eq 1 ] && exit 1 || exit 0
