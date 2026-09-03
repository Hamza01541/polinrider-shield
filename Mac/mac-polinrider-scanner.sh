#!/usr/bin/env bash
# PolinRider / Beavertail / TasksJacker comprehensive scanner — macOS
# IOCs from https://github.com/OpenSourceMalware/PolinRider (campaign tracking)
#
# Usage:
#   bash check-polinrider-mac.sh                          # quick (default paths)
#   bash check-polinrider-mac.sh --repos ~/Documents      # also scan repos under a path
#   sudo -A bash check-polinrider-mac.sh --full           # adds unified-log search
#
# Exits 0 if clean, non-zero with hit count.

set -u
set +H
# sudo bash sets HOME to /var/root; keep Part B on the invoking user's home.
if [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ]; then
  _sudo_home=$(eval echo "~${SUDO_USER}")
  [ -d "$_sudo_home" ] && HOME="$_sudo_home"
  unset _sudo_home
fi
RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; DIM=$'\033[2m'; BLU=$'\033[34m'; RST=$'\033[0m'
hits=0; warns=0
section() { printf "\n${BLU}═══ %s ═══${RST}\n" "$1"; }
sub()     { printf "\n${DIM}── %s ──${RST}\n" "$1"; }
hit()     { printf "  ${RED}⚠ HIT:${RST} %s\n" "$1"; hits=$((hits+1)); }
warn()    { printf "  ${YEL}? REVIEW:${RST} %s\n" "$1"; warns=$((warns+1)); }
ok()      { printf "  ${GRN}✓${RST} %s\n" "$1"; }
note()    { printf "  ${DIM}·${RST} %s\n" "$1"; }

REPO_ROOTS=("$HOME/Documents/GitHub")  # default; override with --repos PATH
FULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --repos) shift; REPO_ROOTS=("$1"); shift ;;
    --full)  FULL=1; shift ;;
    *) shift ;;
  esac
done

# ═════════════════════ IOC CONSTANTS ═════════════════════
# Variant 1 (rmcej_otb_payload, original, ~Mar 2026)
V1_MARKER='rmcej%otb%'
V1_GLOBAL="global\\['!'\\]='8-1638-2'"
V1_SEED1='2857687'
V1_SEED2='2667686'
V1_DECODER='_\\\$_1e42'

# Variant 2 (Cot%3t=shtP, post YARA-rule rotation, ~Apr 2026)
V2_MARKER='Cot%3t=shtP'
V2_SEED1='1111436'
V2_SEED2='3896884'
V2_DECODER='MDy'

# Blockchain dead-drops
TRON_ADDRS='TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG'
BSC_TX='0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e|0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3'

# Network IOCs
C2_IP='166\.88\.54\.158'
C2_VERCEL='260120\.vercel\.app|default-configuration\.vercel\.app|vscode-settings-bootstrap\.vercel\.app|vscode-settings-config\.vercel\.app|vscode-bootstrapper\.vercel\.app|vscode-load-config\.vercel\.app'
C2_RPC='api\.trongrid\.io|api\.telegram\.org|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com'

# Propagation IOCs
PROPAGATION='temp_auto_push\.bat|temp_interactive_push\.bat'

# Malicious npm packages (publicly documented)
EVIL_NPM='tailwindcss-style-animate'

# Weaponized take-home UUIDs
EVIL_UUIDS='e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'

# PolinRider VS Code / fake-font vector (TasksJacker)
FA_SOLID_WOFF2_RE='public/fonts/fa-solid-400.woff2|fa-solid-400.woff2'
TASKSJACKER_CMD_RE='node[[:space:]]+(./)?public/fonts/fa-solid-400.woff2'


# Combined regex for fast file-content scans
ALL_SIG="$V1_MARKER|$V2_MARKER|$V1_GLOBAL|$TRON_ADDRS|$BSC_TX|$C2_IP|$C2_VERCEL"

# Beavertail staging directory pattern: {user}${host}_{YYMMDD_HHMMSS}
NPM_DIR_RE='[a-zA-Z0-9._-]+\$[a-zA-Z0-9._-]+_[0-9]{6}_[0-9]{6}'
EXFIL_ZIP_RE='\$[a-zA-Z0-9._-]+_[0-9]{6}_[0-9]{6}(_2)?#[a-f0-9]{6,}\.zip$'

# Build-config files commonly targeted
BUILD_CFG_GLOB='tailwind.config.* vite.config.* postcss.config.* next.config.* nuxt.config.* eslint.config.* svelte.config.* astro.config.* webpack.config.* rollup.config.*'


# Dedup REPO_ROOTS: drop any root that is a subdirectory of another in the list.
dedup_roots() {
  local r1 r2 keep
  local out=()
  for r1 in "${REPO_ROOTS[@]}"; do
    [ -d "$r1" ] || continue
    keep=1
    for r2 in "${REPO_ROOTS[@]}"; do
      [ "$r1" = "$r2" ] && continue
      [ -d "$r2" ] || continue
      case "$r1/" in "$r2"/*) keep=0; break;; esac
    done
    [ "$keep" = 1 ] && out+=("$r1")
  done
  REPO_ROOTS=("${out[@]}")
}
dedup_roots
echo "Scanning roots: ${REPO_ROOTS[*]}"

# Known compromise: 2026-08-12. log show --start with no --end is that instant
# through NOW (not a 2-day window). Replaces the old rolling "--last 14d".
# macOS unified logs may still have rotated; empty results mean "not in the
# log store", not "clean".
LOG_START='2026-08-11 00:00:00'

# Allow per-section timeouts: bash 'timeout' isn't builtin on macOS; use coreutils gtimeout if installed.
RUN_WITH_TIMEOUT() { if command -v gtimeout >/dev/null; then gtimeout "$1" "${@:2}"; else "${@:2}"; fi }


# ═════════════════ ONE-TIME FILE INVENTORY (avoids repeated find walks) ═════════════════
# macOS /bin/bash is 3.2: process substitution <(cmd) is not quote-aware, so a
# ')' inside a regex like '\.(js|ts)$' closes <( early and crashes with
# "syntax error near unexpected token ')'" / "` -50)'". Use temp files instead.
INV=$(mktemp /tmp/polinrider-inv.XXXXXX)
LIST=$(mktemp /tmp/polinrider-list.XXXXXX)
trap 'rm -f "$INV" "$LIST"' EXIT

grep_list_files() {
  local pat="$1" max="${2:-50}" hits
  hits=$(mktemp /tmp/polinrider-hits.XXXXXX)
  if [ -s "$LIST" ]; then
    tr '\n' '\0' < "$LIST" | xargs -0 grep -lE "$pat" 2>/dev/null | head -n "$max" > "$hits" || true
  else
    : > "$hits"
  fi
  mv "$hits" "$LIST"
}

echo "Building file inventory…"
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 8 -type f \
    -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -not -path "*/venv/*" -not -path "*/.venv/*" \
    -not -path "*/dist/*" -not -path "*/build/*" \
    -not -path "*/.next/*" -not -path "*/.nuxt/*" \
    -not -path "*/target/*" -not -path "*/__pycache__/*" \
    2>/dev/null
done > "$INV"
total=$(wc -l < "$INV" | tr -d ' ')
echo "Inventory: $total files"

section "PART A — REPO PAYLOAD SCAN"

sub "A1. JS payload signatures in tracked source files (both variants)"
found=0
grep -E '\.js$|\.mjs$|\.cjs$|\.ts$|\.tsx$|\.jsx$|\.vue$|\.svelte$' "$INV" > "$LIST" 2>/dev/null || true
grep_list_files "$V1_MARKER|$V2_MARKER|$V1_GLOBAL" 50
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hit "$f"; found=1
done < "$LIST"
[ "$found" = 0 ] && ok "no payload-signature matches in scanned repo trees"

sub "A2. Fake font/asset payloads (wrong magic + signature)"
found=0
grep -E '\.woff2$|\.woff$|\.ttf$' "$INV" > "$LIST" 2>/dev/null || true
while IFS= read -r f; do
  [ -n "$f" ] && [ -f "$f" ] || continue
  magic=$(head -c 4 "$f" 2>/dev/null | xxd -p)
  case "$f" in
    *.woff2) want='774f4632' ;;
    *.woff)  want='774f4646' ;;
    *.ttf)   want='00010000|74727565|4f54544f' ;;
    *) want='' ;;
  esac
  [ -z "$want" ] && continue
  if ! echo "$magic" | grep -qE "^($want)$"; then
    if grep -qE "$V1_MARKER|$V2_MARKER|$V1_GLOBAL|require|process\.|child_process" "$f" 2>/dev/null; then
      hit "$f (magic=$magic, looks like JS not font)"
      found=1
    fi
  fi
done < "$LIST"
[ "$found" = 0 ] && ok "no fake font/asset files detected"


sub "A2b. PolinRider canonical fake font (public/fonts/fa-solid-400.woff2)"
found=0
grep -E 'fa-solid-400\.woff2$' "$INV" > "$LIST" 2>/dev/null || true
if [ ! -s "$LIST" ]; then
  find "${REPO_ROOTS[@]}" -path "*/public/fonts/fa-solid-400.woff2" > "$LIST" 2>/dev/null || true
fi
while IFS= read -r f; do
  [ -f "$f" ] || continue
  magic=$(head -c 4 "$f" 2>/dev/null | xxd -p)
  if ! echo "$magic" | grep -qE "^774f4632$"; then
    if grep -qE "$V1_MARKER|$V2_MARKER|$V1_GLOBAL|$TASKSJACKER_CMD_RE|rmcej" "$f" 2>/dev/null || [ "$(file -b "$f" 2>/dev/null)" = "ASCII text" ]; then
      hit "$f (PolinRider fake fa-solid-400.woff2; magic=$magic)"; found=1
    fi
  fi
done < "$LIST"
[ "$found" = 0 ] && ok "no PolinRider fa-solid-400.woff2 payload file"

sub "A3. Malicious .vscode/tasks.json with auto-execute (TasksJacker)"
found=0
grep -E '/\.vscode/tasks\.json$' "$INV" > "$LIST" 2>/dev/null || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if grep -qE "runOn[\"' ]*:[\"' ]*folderOpen" "$f" 2>/dev/null; then
    if grep -qE "node[[:space:]]+.*\.(woff|ttf|eot)|curl[^|]*\| *(bash|sh|zsh)|wget[^|]*\| *(bash|sh|zsh)|$C2_VERCEL|$C2_RPC|$EVIL_UUIDS" "$f" 2>/dev/null; then
      hit "$f"; found=1
    else
      warn "$f has runOn:folderOpen — manually review"
    fi
  fi
done < "$LIST"
[ "$found" = 0 ] && [ "$warns" = 0 ] && ok "no folderOpen auto-execute tasks.json found"

sub "A3b. TasksJacker canonical node-on-woff2 command"
found=0
grep -E '/\.vscode/tasks\.json$' "$INV" > "$LIST" 2>/dev/null || true
while IFS= read -r f; do
  [ -f "$f" ] || continue
  grep -qE "$TASKSJACKER_CMD_RE" "$f" 2>/dev/null && { hit "$f (node public/fonts/fa-solid-400.woff2)"; found=1; }
done < "$LIST"
[ "$found" = 0 ] && ok "no canonical TasksJacker command in tasks.json"

sub "A4. .vscode/settings.json with task.allowAutomaticTasks:true (auto-task enabler)"
found=0
grep -E '/\.vscode/settings\.json$' "$INV" > "$LIST" 2>/dev/null || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if grep -qE '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*true' "$f" 2>/dev/null; then
    warn "$f sets allowAutomaticTasks:true (review for hidden tasks block)"
    found=1
  fi
done < "$LIST"
[ "$found" = 0 ] && ok "no allowAutomaticTasks:true settings.json found"

sub "A5. Propagation script names referenced in any repo"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  grep -rlI \
            --include=".gitignore" --include="*.md" --include="*.json" --include="*.yml" --include="*.yaml" \
            --include="*.sh" --include="*.bat" --include="*.cmd" --include="*.ps1" --include="*.txt" \
            --include="*.js" --include="*.mjs" --include="*.cjs" --include="*.ts" \
            --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=venv --exclude-dir=.next \
            --exclude-dir=dist --exclude-dir=build --exclude-dir=.nuxt \
            -E "$PROPAGATION" "$root" 2>/dev/null | head -n 50 > "$LIST" || true
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    hit "$f references temp_auto_push/temp_interactive_push"; found=1
  done < "$LIST"
done
[ "$found" = 0 ] && ok "no propagation-script references"

sub "A6. Malicious npm package '$EVIL_NPM' in package.json files"
found=0
grep -E '/package\.json$' "$INV" > "$LIST" 2>/dev/null || true
grep_list_files "$EVIL_NPM" 50
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hit "$f depends on $EVIL_NPM"; found=1
done < "$LIST"
[ "$found" = 0 ] && ok "no malicious-npm dep '$EVIL_NPM'"

sub "A7. Weaponized take-home UUIDs ($EVIL_UUIDS)"
found=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  grep -rlE "$EVIL_UUIDS" --include="*.json" --exclude-dir=node_modules --exclude-dir=.git "$root" 2>/dev/null | head -n 20 > "$LIST" || true
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    hit "$f"; found=1
  done < "$LIST"
done
[ "$found" = 0 ] && ok "no take-home UUID matches"

sub "A8. Git history: commits with TZ-mismatch spoofing fingerprint (last 500 commits per repo)"
# Author tz != committer tz with same identity = post-commit amend on different machine
found=0
repo_count=0
for root in "${REPO_ROOTS[@]}"; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 4 -name .git -type d 2>/dev/null | sed 's/\/.git$//' > "$LIST"
  while IFS= read -r repo; do
    repo_count=$((repo_count+1))
    cd "$repo" 2>/dev/null || continue
    suspicious=$(git log --all -n 500 --format='%h|%ai|%ci|%ae|%ce|%s' 2>/dev/null | awk -F'|' '
      { atz=substr($2,length($2)-4); ctz=substr($3,length($3)-4);
        if (atz != ctz && $4 == $5) print $1" "atz"/"ctz" "$4" "substr($6,1,50) }' | head -3)
    if [ -n "$suspicious" ]; then warn "$repo"; echo "$suspicious" | sed 's/^/      /'; found=1; fi
  done < "$LIST"
done
note "scanned $repo_count repos"
[ "$found" = 0 ] && ok "no commits with author/committer TZ-mismatch + same identity"

section "PART B — HOST EXECUTION-EVIDENCE SCAN"

sub "B1. Beavertail staging directories"
found=0
for base in "$HOME/.npm" "/tmp" "/var/tmp" "$HOME/Library/Application Support" "$HOME/Library/Caches"; do
  [ -d "$base" ] || continue
  find "$base" -maxdepth 3 -type d 2>/dev/null | grep -E "/$NPM_DIR_RE\$" | head -n 10 > "$LIST" || true
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    hit "$d"; found=1
  done < "$LIST"
done
[ "$found" = 0 ] && ok "no Beavertail staging directories"

sub "B2. Beavertail staged file names (_credentials.json, _sysenv.json, _info.json)"
found=0
find "$HOME/.npm" "/tmp" "/var/tmp" "$HOME/Library/Application Support" "$HOME/Library/Caches" \
   \( -name "_credentials.json" -o -name "_sysenv.json" -o -name "_sysenv.env" -o -name "_info.json" \) \
   2>/dev/null | head -n 20 > "$LIST" || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  hit "$f"; found=1
done < "$LIST"
[ "$found" = 0 ] && ok "no staged credential/sysenv/info JSON files"

sub "B3. Exfil archive '{user}\${host}_*#{hash}.zip'"
found=0
find "$HOME" -maxdepth 6 -type f -name "*.zip" 2>/dev/null | grep -E "$EXFIL_ZIP_RE" | head -n 10 > "$LIST" || true
while IFS= read -r z; do
  [ -n "$z" ] || continue
  hit "$z"; found=1
done < "$LIST"
[ "$found" = 0 ] && ok "no exfil-pattern archives"

sub "B4. Lock files (tmp7A863DD1.tmp and other Beavertail mutexes)"
found=0
for lf in /tmp/tmp7A863DD1.tmp "$HOME/Library/Caches/tmp7A863DD1.tmp" /var/tmp/tmp7A863DD1.tmp; do
  [ -e "$lf" ] && { hit "$lf"; found=1; }
done
[ "$found" = 0 ] && ok "no known lock files"

sub "B5. LaunchAgents/Daemons referencing IOCs (persistence)"
found=0
for dir in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
  [ -d "$dir" ] || continue
  find "$dir" -name "*.plist" 2>/dev/null > "$LIST" || true
  while IFS= read -r plist; do
    [ -e "$plist" ] || continue
    if grep -qiE "(node[[:space:]]+.*\.(woff|woff2|ttf|eot)|node[[:space:]]+.*fonts/|$C2_RPC|$C2_VERCEL|$C2_IP|$TRON_ADDRS|/tmp/[a-f0-9]+\.(js|py)|\.npm/.*\\\$.*_[0-9]{6}_[0-9]{6})" "$plist" 2>/dev/null; then
      hit "$plist"; found=1
    fi
  done < "$LIST"
done
[ "$found" = 0 ] && ok "no plists reference IOC strings"

sub "B6. Recently-modified plists for manual review (last 90d)"
recent=$(find "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
            -name "*.plist" -mtime -90 2>/dev/null)
if [ -z "$recent" ]; then ok "none"
else echo "$recent" | sed 's/^/    · /'; fi

sub "B7. login items / login-items.plist"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
  | tr ',' '\n' | sed 's/^[[:space:]]*//' | while read -r li; do
    case "$li" in
      ""|"missing value") ;;
      *) note "login item: $li" ;;
    esac
  done

sub "B8. Dropper-shaped files with IOC content (/tmp, ~/Library, last 180d)"
found=0
find "/tmp" "/var/tmp" "$HOME/Library/Caches" "$HOME/Library/Application Support" \
            -maxdepth 4 -type f \( -name "*.py" -o -name "*.js" -o -name "*.sh" \) \
            -mtime -180 2>/dev/null | head -n 500 > "$LIST" || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if grep -qE "$C2_RPC|$C2_IP|$TRON_ADDRS|$BSC_TX|portalocker|tmp7A863DD1|$V1_MARKER|$V2_MARKER" "$f" 2>/dev/null; then
    hit "$f"; found=1
  fi
done < "$LIST"
[ "$found" = 0 ] && ok "no droppers matching IOC content"

sub "B9. Running processes referencing IOCs"
ps_hits=$(ps auxww 2>/dev/null | grep -iE "node[[:space:]]+.*\.(woff|woff2|ttf|eot)|node[[:space:]]+.*fonts/|$C2_RPC|$C2_IP|$C2_VERCEL" | grep -v grep | grep -v check-polinrider)
if [ -n "$ps_hits" ]; then hit "process matches:"; echo "$ps_hits" | sed 's/^/    /'
else ok "no running processes match IOCs"; fi

sub "B10. Open network connections to known C2"
net_hits=$(lsof -i -nP 2>/dev/null | grep -iE "$C2_IP|telegram|trongrid|260120|default-configuration|vscode-settings|vscode-bootstrapper|vscode-load-config" | head -20)
if [ -n "$net_hits" ]; then hit "open connection match:"; echo "$net_hits" | sed 's/^/    /'
else ok "no live connections to C2 endpoints"; fi

sub "B11. DNS resolver cache for IOC domains"
# NOTE: macOS has no passive way to read the resolver cache without forcing a lookup.
# We skip active probing (which would create false positives by triggering resolution).
# Instead, run B10 above (live connections) and below (sudo log search) for evidence.
note "skipped (active probing would create false positives — see Part C log search instead)"

sub "B12. Shell history search for IOC strings"
hist_hits=$(grep -hE "$C2_RPC|$C2_IP|$C2_VERCEL|$TRON_ADDRS|$V1_MARKER|$V2_MARKER|$PROPAGATION|fa-solid-400\.woff2" \
   "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME/.history" 2>/dev/null | head -10)
if [ -n "$hist_hits" ]; then hit "shell history mentions IOCs:"; echo "$hist_hits" | sed 's/^/    /'
else ok "shell history clean"; fi

sub "B13. Browser credential DB last-modified (informational)"
db_paths=(
  "$HOME/Library/Application Support/Google/Chrome/Default/Login Data"
  "$HOME/Library/Application Support/Google/Chrome/Default/Cookies"
  "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data"
  "$HOME/Library/Application Support/Microsoft Edge/Default/Login Data"
  "$HOME/Library/Application Support/Vivaldi/Default/Login Data"
  "$HOME/Library/Application Support/Arc/User Data/Default/Login Data"
)
for p in "${db_paths[@]}"; do
  [ -f "$p" ] && note "$p  ($(stat -f '%Sm' "$p" 2>/dev/null))"
done
ff="$HOME/Library/Application Support/Firefox/Profiles"
[ -d "$ff" ] && find "$ff" -name "logins.json" 2>/dev/null | head -5 | while read -r f; do note "$f  ($(stat -f '%Sm' "$f"))"; done

sub "B14. Crypto wallet directories (informational — do you have crypto wallets installed?)"
for w in \
  "$HOME/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" \
  "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" \
  "$HOME/Library/Application Support/Exodus" \
  "$HOME/Library/Application Support/atomic" \
  "$HOME/Library/Application Support/Electrum" \
  "$HOME/Library/Application Support/Coinomi" \
  "$HOME/Library/Application Support/Phantom" \
  "$HOME/Library/Application Support/Solflare"; do
  [ -e "$w" ] && note "wallet found: $w  ($(stat -f '%Sm' "$w" 2>/dev/null))"
done

sub "B15. Keychain access log (since $LOG_START)"
log show --predicate 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS[c] "keychain"' --start "$LOG_START" 2>/dev/null \
  | grep -iE "node|python|curl|wget" | head -10

if [ "$FULL" = 1 ]; then
  section "PART C — DEEP SYSTEM-LOG SCAN (sudo required)"
  if [ "$(id -u)" = "0" ]; then
    sub "C1. Unified log search (since $LOG_START, can take several minutes)"
    log show --predicate 'eventMessage CONTAINS[c] "trongrid" OR eventMessage CONTAINS[c] "166.88.54.158" OR eventMessage CONTAINS[c] "260120.vercel.app" OR eventMessage CONTAINS[c] "default-configuration.vercel.app" OR eventMessage CONTAINS[c] "TMfKQEd" OR eventMessage CONTAINS[c] "TXfxHUet" OR eventMessage CONTAINS[c] "fa-solid-400.woff2" OR eventMessage CONTAINS[c] "vscode-settings-bootstrap" OR eventMessage CONTAINS[c] "vscode-bootstrapper"' --start "$LOG_START" 2>/dev/null | head -100 | sed 's/^/    /'
    sub "C2. All users' processes"
    ps auxww 2>/dev/null | grep -iE "node.*\.(woff|ttf)|node.*fonts/|$C2_IP|$C2_RPC" | grep -v grep | grep -v check-polinrider | sed 's/^/    /'
    sub "C3. pf state table for known C2 IPs"
    pfctl -s state 2>/dev/null | grep -E "$C2_IP" | head -10 | sed 's/^/    /'
  else
    note "skip — re-run with: sudo -A bash $0 --full"
  fi
fi

section "SUMMARY"
if [ "$hits" = 0 ] && [ "$warns" = 0 ]; then
  printf "  ${GRN}No IOC matches and no items requiring review.${RST}\n"
elif [ "$hits" = 0 ]; then
  printf "  ${YEL}%d item(s) flagged for manual review (no confirmed hits).${RST}\n" "$warns"
else
  printf "  ${RED}%d HIT(s)${RST}, ${YEL}%d for manual review${RST}.\n" "$hits" "$warns"
fi
printf "  ${DIM}A clean scan does not prove uninfection — Beavertail variants self-clean.${RST}\n"
exit "$hits"
