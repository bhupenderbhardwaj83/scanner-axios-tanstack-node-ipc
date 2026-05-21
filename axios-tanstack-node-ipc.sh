#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  axios-tanstack-node-ipc.sh  —  Supply-Chain Vulnerability Scanner  v1.1 - By Design Engineer - Network18
#
#  Detects:
#    ① TanStack  CVE-2026-45321  (84 malicious versions, May 11 2026)
#    ② node-ipc  backdoor        (9.1.6 / 9.2.3 / 12.0.1)
#    ③ Axios     compromise      (1.14.1 / 0.30.4 + plain-crypto-js)
#
#  Package managers: npm · pnpm · yarn classic/berry · bun
#  Modes:  [1] Full scan  [2] Project scan (path)  [3] Fast scan (~30s)
#  Output: colour console + log file written to the directory you run from
# ══════════════════════════════════════════════════════════════════════════════
set -eo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m';  BR='\033[1;31m'
Y='\033[1;33m';  BY='\033[1;93m'
G='\033[0;32m';  BG='\033[1;32m'
C='\033[0;36m';  BC='\033[1;36m'
M='\033[0;35m';  BM='\033[1;35m'
W='\033[1;37m';  DIM='\033[2m'
BOLD='\033[1m';  NC='\033[0m'

# ── Log setup ─────────────────────────────────────────────────────────────────
LOGFILE="$(pwd)/vuln_scan_$(date +%Y%m%d_%H%M%S).log"
COMPROMISE_DATE_START="2026-05-10"
COMPROMISE_DATE_END="2026-05-14"

_log()    { echo -e "$*" | tee -a "$LOGFILE"; }
banner()  { _log "\n${BOLD}${BC}$*${NC}"; }
sep()     { _log "${DIM}  ────────────────────────────────────────────────────────${NC}"; }
sep2()    { _log "\n${BOLD}${W}══════════════════════════════════════════════════════════${NC}"; }
hit()     { TOTAL_HITS=$((TOTAL_HITS+1));   SEC_HITS=$((SEC_HITS+1));   _log "${BR}  ◉ [HIT] ${NC}${R}$*${NC}"; }
warn()    { TOTAL_WARNS=$((TOTAL_WARNS+1)); SEC_WARNS=$((SEC_WARNS+1)); _log "${Y}  ⚠ [WARN]${NC} $*"; }
ok()      { _log "${BG}  ✔ [OK]  ${NC}${G}$*${NC}"; }
info()    { _log "${C}  ℹ [INFO]${NC} $*"; }
detail()  { _log "${DIM}         $*${NC}"; }
progress(){ _log "${DIM}  ┄ $* … [$(elapsed)]${NC}"; }

TOTAL_HITS=0; TOTAL_WARNS=0
SEC1_HITS=0;  SEC1_WARNS=0
SEC2_HITS=0;  SEC2_WARNS=0
SEC3_HITS=0;  SEC3_WARNS=0
SEC_HITS=0;   SEC_WARNS=0

SCAN_START=0
elapsed() { printf "%ds" "$((SECONDS - SCAN_START))"; }

# ── SHA-256 ───────────────────────────────────────────────────────────────────
sha256() {
  local f="$1"
  [[ -f "$f" ]] || { echo "FILE_NOT_FOUND"; return; }
  if   command -v shasum     &>/dev/null; then shasum -a 256 "$f" 2>/dev/null | awk '{print $1}'
  elif command -v sha256sum  &>/dev/null; then sha256sum       "$f" 2>/dev/null | awk '{print $1}'
  elif command -v openssl    &>/dev/null; then openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}'
  else echo "NO_SHA_TOOL"
  fi
}

# ── Stat date helper (macOS BSD stat) ────────────────────────────────────────
file_date() { stat -f "%Sm" -t "%Y-%m-%d" "$1" 2>/dev/null || echo "?"; }

in_risk_window() {
  local d="$1"
  [[ "$d" > "$COMPROMISE_DATE_START" && "$d" < "$COMPROMISE_DATE_END" ]]
}

# ── Python: check if pkg@ver exists in any lockfile format ───────────────────
lockfile_has_pkg_ver() {
  local lf="$1" pkg="$2" ver="$3"
  python3 - "$lf" "$pkg" "$ver" <<'PY' 2>/dev/null
import sys, json, re
lf, pkg, ver = sys.argv[1], sys.argv[2], sys.argv[3]
bn = lf.rsplit('/', 1)[-1]
try:
  c = open(lf, errors='replace').read()
  if bn in ('package-lock.json', 'npm-shrinkwrap.json'):
    d = json.loads(c)
    for k in (f'node_modules/{pkg}', pkg):
      if d.get('packages', {}).get(k, {}).get('version') == ver: sys.exit(0)
    if d.get('dependencies', {}).get(pkg, {}).get('version') == ver: sys.exit(0)
  elif bn == 'yarn.lock':
    m = re.search(r'"?' + re.escape(pkg) + r'@[^":\n]*"?:\n(?:[^\n]*\n)*?\s+version[: ]+"?'
                  + re.escape(ver) + r'"?', c)
    if m: sys.exit(0)
  elif bn == 'pnpm-lock.yaml':
    if re.search(re.escape(pkg) + r'@' + re.escape(ver) + r'[^0-9a-zA-Z.\-]', c): sys.exit(0)
  elif bn in ('bun.lock',):
    if f'"{pkg}@' in c and ver in c: sys.exit(0)
except Exception: pass
sys.exit(1)
PY
}

# ── Python: get all versions of a package from a lockfile ────────────────────
lockfile_pkg_versions() {
  local lf="$1" pkg="$2"
  python3 - "$lf" "$pkg" <<'PY' 2>/dev/null
import sys, json, re
lf, pkg = sys.argv[1], sys.argv[2]
bn = lf.rsplit('/', 1)[-1]
found = set()
try:
  c = open(lf, errors='replace').read()
  if bn in ('package-lock.json', 'npm-shrinkwrap.json'):
    d = json.loads(c)
    for k, v in d.get('packages', {}).items():
      if pkg in k: found.add(v.get('version', ''))
    dep = d.get('dependencies', {}).get(pkg, {})
    if dep.get('version'): found.add(dep['version'])
  elif bn == 'yarn.lock':
    for m in re.finditer(r'"?' + re.escape(pkg) + r'@[^":\n]*"?:\n(?:[^\n]*\n)*?\s+version[: ]+"?([0-9][^"\n ]*)', c):
      found.add(m.group(1))
  elif bn == 'pnpm-lock.yaml':
    for m in re.finditer(re.escape(pkg) + r'@([0-9][^:\'/"\n (]*)', c):
      found.add(m.group(1))
  elif bn == 'bun.lock':
    for m in re.finditer(r'"' + re.escape(pkg) + r'@npm:([0-9][^"]*)"', c):
      found.add(m.group(1))
except Exception: pass
print('\n'.join(v for v in sorted(found) if v))
PY
}

# ── Python: check optionalDependencies ───────────────────────────────────────
pkg_json_has_optional_dep() {
  local pj="$1" pat="$2"
  python3 - "$pj" "$pat" <<'PY' 2>/dev/null
import sys, json, re
pj, pat = sys.argv[1], sys.argv[2]
try:
  d = json.load(open(pj, errors='replace'))
  for k in d.get('optionalDependencies', {}):
    if re.search(pat, k): sys.exit(0)
except Exception: pass
sys.exit(1)
PY
}

# ── Bun lockfile reader ───────────────────────────────────────────────────────
read_bun_lockfile() {
  local f="$1"
  if command -v bun &>/dev/null; then
    bun "$f" 2>/dev/null || strings "$f" 2>/dev/null
  else
    strings "$f" 2>/dev/null
  fi
}

# ── Find helpers: common exclusion flags ─────────────────────────────────────
# Usage: find_excl → expands to -not -path ... flags for noise dirs
find_excl() {
  echo \
    -not -path "*/node_modules/.cache/*" \
    -not -path "*/.git/*" \
    -not -path "*/.cache/*" \
    -not -path "*/_cacache/*" \
    -not -path "*/Library/Caches/*" \
    -not -path "*/Library/CloudStorage/*" \
    -not -path "*/Library/Group Containers/*" \
    -not -path "*/.Trash/*"
}

# ══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════════════
clear
_log ""
_log "${BOLD}${BC}╔══════════════════════════════════════════════════════════════╗${NC}"
_log "${BOLD}${BC}║   Supply-Chain Vulnerability Scanner  ·  v1.1               ║${NC}"
_log "${BOLD}${BC}║   TanStack CVE-2026-45321  ·  node-ipc  ·  Axios            ║${NC}"
_log "${BOLD}${BC}║   npm · pnpm · yarn · bun                                   ║${NC}"
_log "${BOLD}${BC}╚══════════════════════════════════════════════════════════════╝${NC}"
_log ""
_log "  ${DIM}Log → $LOGFILE${NC}"
_log "  ${DIM}$(date)${NC}"
_log ""

# ══════════════════════════════════════════════════════════════════════════════
#  MENU
# ══════════════════════════════════════════════════════════════════════════════
_log "${BOLD}  Select scan mode:${NC}"
_log ""
_log "  ${BY}[1]${NC}  Full computer scan   ${DIM}(searches \$HOME + common dev dirs — 2-5 min)${NC}"
_log "  ${BY}[2]${NC}  Project scan         ${DIM}(you specify a directory path, or press Enter for $(pwd))${NC}"
_log "  ${BY}[3]${NC}  Fast scan            ${DIM}(lockfiles + globals + IOC files only — ~30 seconds, 90%+ accuracy)${NC}"
_log ""
printf "  ${BOLD}Enter choice [1/2/3]: ${NC}" | tee -a "$LOGFILE"
read -r SCAN_CHOICE
_log "  → Selected: $SCAN_CHOICE"
_log ""

FAST_MODE=0
MAXDEPTH=12

case "$SCAN_CHOICE" in
  2)
    SCAN_MODE="project"
    printf "  ${BOLD}Directory path (press Enter for current dir): ${NC}" | tee -a "$LOGFILE"
    read -r CUSTOM_PATH
    _log ""
    if [[ -n "$CUSTOM_PATH" && -d "$CUSTOM_PATH" ]]; then
      SCAN_ROOTS=("$CUSTOM_PATH")
      _log "  ${G}Mode: Project scan → $CUSTOM_PATH${NC}"
    elif [[ -n "$CUSTOM_PATH" ]]; then
      _log "  ${Y}Path not found: $CUSTOM_PATH — falling back to $(pwd)${NC}"
      SCAN_ROOTS=("$(pwd)")
    else
      SCAN_ROOTS=("$(pwd)")
      _log "  ${G}Mode: Project scan → $(pwd)${NC}"
    fi
    MAXDEPTH=8
    ;;
  3)
    SCAN_MODE="fast"
    FAST_MODE=1
    SCAN_ROOTS=("$HOME" "/Users/Shared")
    [[ -d "$HOME/Developer" ]] && SCAN_ROOTS+=("$HOME/Developer")
    [[ -d "$HOME/Projects"  ]] && SCAN_ROOTS+=("$HOME/Projects")
    [[ -d "$HOME/workspace" ]] && SCAN_ROOTS+=("$HOME/workspace")
    [[ -d "$HOME/src"       ]] && SCAN_ROOTS+=("$HOME/src")
    MAXDEPTH=10
    _log "  ${G}Mode: Fast scan — lockfiles + globals + IOC files (~30 seconds)${NC}"
    ;;
  *)
    SCAN_MODE="full"
    SCAN_ROOTS=("$HOME" "/Users/Shared")
    [[ -d "$HOME/Developer" ]] && SCAN_ROOTS+=("$HOME/Developer")
    [[ -d "$HOME/Projects"  ]] && SCAN_ROOTS+=("$HOME/Projects")
    [[ -d "$HOME/workspace" ]] && SCAN_ROOTS+=("$HOME/workspace")
    [[ -d "$HOME/src"       ]] && SCAN_ROOTS+=("$HOME/src")
    _log "  ${G}Mode: Full computer scan${NC}"
    ;;
esac

SCAN_START=$SECONDS

# ── Collect all lockfiles once ────────────────────────────────────────────────
_log ""
progress "Collecting lockfiles (npm / pnpm / yarn / bun)"

LOCKFILES=()
while IFS= read -r f; do LOCKFILES+=("$f"); done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    \( \
      -name "package-lock.json" -o \
      -name "npm-shrinkwrap.json" -o \
      -name "yarn.lock" -o \
      -name "pnpm-lock.yaml" -o \
      -name "bun.lock" -o \
      -name "bun.lockb" \
    \) \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/.cache/*" \
    -not -path "*/_cacache/*" \
    -not -path "*/Library/Caches/*" \
    -not -path "*/Library/CloudStorage/*" \
    -not -path "*/Library/Group Containers/*" \
    -not -path "*/.Trash/*" \
    2>/dev/null | sort -u | head -300
)

info "Found ${#LOCKFILES[@]} lockfile(s) in $(elapsed)"
if [[ ${#LOCKFILES[@]} -gt 0 ]]; then
  for lf in "${LOCKFILES[@]}"; do
    pm=$(basename "$lf")
    detail "$(file_date "$lf")  [$pm]  $lf"
  done
fi

# ══════════════════════════════════════════════════════════════════════════════
sep2
banner "SECTION 1  —  TanStack  (CVE-2026-45321)  [$(elapsed)]"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}84 malicious versions across 42 \`@tanstack/*\` packages published May 11 2026.${NC}"
_log "  ${DIM}IOC files: router_init.js · tanstack_runner.js · router_runtime.js${NC}"
_log "  ${DIM}Known bad version examples: @tanstack/react-router@1.169.5, @tanstack/router-core@1.169.5${NC}"
_log ""

SEC_HITS=0; SEC_WARNS=0

TANSTACK_PKGS=(
  "@tanstack/react-query"     "@tanstack/query-core"
  "@tanstack/query-devtools"  "@tanstack/react-table"
  "@tanstack/react-router"    "@tanstack/router"
  "@tanstack/router-core"     "@tanstack/router-devtools"
  "@tanstack/react-form"      "@tanstack/form-core"
  "@tanstack/store"           "@tanstack/virtual"
  "@tanstack/react-virtual"   "@tanstack/vue-query"
  "@tanstack/solid-query"     "@tanstack/svelte-query"
  "@tanstack/start"           "@tanstack/eslint-plugin-query"
  "@tanstack/angular-query-experimental"
)
TANSTACK_BAD_VERSIONS=("1.169.5" "1.169.6")

# bash 3.2 compat: use function instead of associative array (declare -A not supported)
ts_ioc_hash() {
  case "$1" in
    "router_init.js")     echo "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" ;;
    "tanstack_runner.js") echo "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" ;;
    *)                    echo "" ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  1a · Lockfile scan  (npm / pnpm / yarn / bun)  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

if [[ ${#LOCKFILES[@]} -eq 0 ]]; then
  info "No lockfiles found — skipping lockfile scan"
else
  for lf in "${LOCKFILES[@]}"; do
    lf_pm=$(basename "$lf")
    lf_date=$(file_date "$lf")
    lf_flagged=0

    if [[ "$lf_pm" == "bun.lockb" ]]; then
      bun_text=$(read_bun_lockfile "$lf")
      for pkg in "${TANSTACK_PKGS[@]}"; do
        for bver in "${TANSTACK_BAD_VERSIONS[@]}"; do
          if echo "$bun_text" | grep -q "${pkg}@${bver}"; then
            hit "Bad version in bun.lockb: ${pkg}@${bver}"
            detail "File: $lf"
            lf_flagged=1
          fi
        done
      done
      in_risk_window "$lf_date" && { hit "bun.lockb modified DURING risk window ($lf_date): $lf"; lf_flagged=1; }
      [[ $lf_flagged -eq 0 ]] && ok "Clean [bun.lockb]: $(basename "$(dirname "$lf")")/bun.lockb"
      continue
    fi

    for pkg in "${TANSTACK_PKGS[@]}"; do
      grep -qF "$pkg" "$lf" 2>/dev/null || continue
      for bver in "${TANSTACK_BAD_VERSIONS[@]}"; do
        if lockfile_has_pkg_ver "$lf" "$pkg" "$bver"; then
          hit "BAD VERSION in [$lf_pm]: ${pkg}@${bver}"
          detail "File: $lf"
          lf_flagged=1
        fi
      done
      installed_vers=$(lockfile_pkg_versions "$lf" "$pkg")
      if [[ -n "$installed_vers" ]]; then
        while IFS= read -r iv; do
          [[ -z "$iv" ]] && continue
          already_bad=0
          for bver in "${TANSTACK_BAD_VERSIONS[@]}"; do [[ "$iv" == "$bver" ]] && already_bad=1; done
          if [[ $already_bad -eq 0 ]]; then
            warn "TanStack present [$lf_pm]: ${pkg}@${iv}"
            detail "File:        $lf"
            detail "Package:     ${pkg}@${iv}"
            detail "Warn type:   Version not in known-bad list — publish date unverified"
            detail "Action:      Run: npm view ${pkg}@${iv} time"
            detail "             IGNORE if publish date is NOT between 2026-05-10 and 2026-05-14"
            detail "             ESCALATE (treat as HIT) if date falls within that window"
          fi
        done <<< "$installed_vers"
      fi
    done

    in_risk_window "$lf_date" && { hit "Lockfile modified DURING risk window ($lf_date): $lf"; lf_flagged=1; }
    [[ $lf_flagged -eq 0 ]] && ok "Clean [$lf_pm]: $(basename "$(dirname "$lf")")/$(basename "$lf")"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  1b · node_modules  —  installed package version + install date  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""
progress "Searching node_modules/@tanstack (single pass)"

# ONE find pass for all @tanstack packages instead of 19 separate traversals
ts_nm_hits=0
while IFS= read -r pkg_json; do
  pkg_name=$(python3 -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('name',''))" 2>/dev/null)
  pkg_ver=$(python3  -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('version','?'))" 2>/dev/null)
  pkg_date=$(file_date "$pkg_json")

  for bver in "${TANSTACK_BAD_VERSIONS[@]}"; do
    if [[ "$pkg_ver" == "$bver" ]]; then
      ts_nm_hits=$((ts_nm_hits+1))
      hit "BAD VERSION INSTALLED: ${pkg_name}@${pkg_ver}"
      detail "Path:      $pkg_json"
      detail "Installed: $pkg_date"
    fi
  done

  if in_risk_window "$pkg_date"; then
    hit "Installed DURING risk window ($pkg_date): ${pkg_name}@${pkg_ver}"
    detail "Path: $pkg_json"
    ts_nm_hits=$((ts_nm_hits+1))
  fi
done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/node_modules/@tanstack/*/package.json" \
    -not -path "*/node_modules/@tanstack/*/*/node_modules/*" \
    -not -path "*/Library/Caches/*" \
    -not -path "*/Library/CloudStorage/*" \
    -not -path "*/Library/Group Containers/*" \
    -not -path "*/.git/*" \
    -not -path "*/.Trash/*" \
    2>/dev/null | head -500
)

[[ $ts_nm_hits -eq 0 ]] && ok "No malicious @tanstack versions found in node_modules [$(elapsed)]"

# pnpm virtual store — one pass
pnpm_ts_hits=0
while IFS= read -r pkg_json; do
  pkg_name=$(python3 -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('name',''))" 2>/dev/null)
  pkg_ver=$(python3  -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('version','?'))" 2>/dev/null)
  pkg_date=$(file_date "$pkg_json")
  for bver in "${TANSTACK_BAD_VERSIONS[@]}"; do
    if [[ "$pkg_ver" == "$bver" ]]; then
      hit "BAD VERSION in pnpm store: ${pkg_name}@${pkg_ver}"
      detail "Path: $pkg_json"
      pnpm_ts_hits=$((pnpm_ts_hits+1))
    fi
  done
done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/.pnpm/@tanstack*/package.json" \
    -not -path "*/Library/CloudStorage/*" \
    2>/dev/null | head -200
)
[[ $pnpm_ts_hits -eq 0 ]] && ok "pnpm store: no malicious @tanstack versions [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  1c · IOC file detection  —  router_init.js · tanstack_runner.js  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""
_log "  ${DIM}Strongest signal: malicious payload files bundled inside @tanstack/* installs${NC}"
_log ""
progress "Searching for IOC filenames (single find pass)"

ioc_found=0
while IFS= read -r found; do
  ioc_file=$(basename "$found")
  actual_hash=$(sha256 "$found")
  expected_hash=$(ts_ioc_hash "$ioc_file")
  ioc_found=1

  if [[ -n "$expected_hash" && "$actual_hash" == "$expected_hash" ]]; then
    hit "IOC FILE CONFIRMED (hash match): $ioc_file"
    detail "Path:    $found"
    detail "SHA-256: $actual_hash  ← MATCHES KNOWN MALICIOUS HASH"
  elif [[ -n "$expected_hash" ]]; then
    warn "IOC filename found but hash DIFFERS (may be variant or legitimate build artifact)"
    detail "File:         $found"
    detail "Actual hash:  $actual_hash"
    detail "Expected IOC: $expected_hash"
  else
    warn "Suspicious filename found in @tanstack dir — inspect manually"
    detail "File:    $found"
    detail "SHA-256: $actual_hash"
  fi
done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/@tanstack/*" \
    \( -name "router_init.js" -o -name "tanstack_runner.js" -o \
       -name "router_runtime.js" -o -name "setup.mjs" \) \
    -not -path "*/Library/CloudStorage/*" \
    -not -path "*/.git/*" \
    -not -path "*/.Trash/*" \
    2>/dev/null
)
[[ $ioc_found -eq 0 ]] && ok "No IOC files found in @tanstack dirs [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  1d · Persistence check  —  .claude/ · .vscode/ · .antigravity/  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

PERSIST_DIRS=(
  "$HOME/.claude"
  "$HOME/.vscode"
  "$HOME/.config/Code/User"
  "$HOME/Library/Application Support/Code/User"
  "$HOME/.antigravity"
)
PERSIST_IOC_FILES=("router_runtime.js" "setup.mjs" "router_init.js" "tanstack_runner.js")
persist_hits=0

for pdir in "${PERSIST_DIRS[@]}"; do
  [[ -d "$pdir" ]] || continue
  for pioc in "${PERSIST_IOC_FILES[@]}"; do
    while IFS= read -r found; do
      hit "PERSISTENCE IOC FILE in editor config dir: $found"
      detail "SHA-256: $(sha256 "$found")"
      persist_hits=$((persist_hits+1))
    done < <(find "$pdir" -name "$pioc" 2>/dev/null)
  done
done
[[ $persist_hits -eq 0 ]] && ok "Persistence file check complete — clean [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
# 1e: optionalDependencies audit (skipped in fast mode — low signal, high I/O)
# ─────────────────────────────────────────────────────────────────────────────
if [[ $FAST_MODE -eq 0 ]]; then
  sep; banner "  1e · package.json audit  —  @tanstack/setup in optionalDependencies  [$(elapsed)]"
  _log ""
  _log "  ${DIM}Compromised packages injected \`@tanstack/setup\` as an optional dep to load the payload${NC}"
  _log ""
  progress "Scanning package.json files"

  optdep_hits=0
  while IFS= read -r pj; do
    [[ "$pj" == *"node_modules"* ]] && continue
    if pkg_json_has_optional_dep "$pj" "@tanstack/setup"; then
      hit "@tanstack/setup in optionalDependencies: $pj"
      optdep_hits=$((optdep_hits+1))
    fi
  done < <(
    find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
      -name "package.json" \
      -not -path "*/node_modules/*" \
      -not -path "*/.git/*" \
      -not -path "*/Library/CloudStorage/*" \
      2>/dev/null | head -500
  )
  [[ $optdep_hits -eq 0 ]] && ok "optionalDependencies scan complete — clean [$(elapsed)]"
else
  info "1e · optionalDependencies scan — skipped in fast mode"
fi

# ── Section 1 summary ─────────────────────────────────────────────────────────
SEC1_HITS=$SEC_HITS; SEC1_WARNS=$SEC_WARNS
_log ""
if   [[ $SEC_HITS  -gt 0 ]]; then
  _log "  ${BR}◉ Section 1 result: ${SEC_HITS} HIT(s) · ${SEC_WARNS} warning(s) — ACTION REQUIRED  [$(elapsed)]${NC}"
  _log "  ${R}  → Remove affected @tanstack/* packages and reinstall from clean registry${NC}"
  _log "  ${R}  → Delete IOC files if found${NC}"
  _log "  ${R}  → Run: npm audit fix   /   pnpm audit --fix   /   yarn npm audit${NC}"
elif [[ $SEC_WARNS -gt 0 ]]; then
  _log "  ${Y}⚠ Section 1 result: 0 confirmed hits · ${SEC_WARNS} package(s) need version verification  [$(elapsed)]${NC}"
  _log "  ${Y}  → Run: npm view @tanstack/<pkg>@<ver> time   to check npm publish date${NC}"
else
  _log "  ${BG}✔ Section 1 result: CLEAN — no TanStack IOCs or bad versions detected  [$(elapsed)]${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2
banner "SECTION 2  —  node-ipc  (backdoor versions 9.1.6 / 9.2.3 / 12.0.1)  [$(elapsed)]"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}StepSecurity disclosure: three node-ipc versions contain an obfuscated payload${NC}"
_log "  ${DIM}that exfiltrates cloud credentials, SSH keys, and CI/CD secrets.${NC}"
_log "  ${DIM}C2: sh.azurestaticprovider.net (IP: 37.16.75.69)${NC}"
_log "  ${DIM}IOC file: node-ipc.cjs  SHA-256: 96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144${NC}"
_log ""

IPC_BAD_VERSIONS=("9.1.6" "9.2.3" "12.0.1")
IPC_CJS_HASH="96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144"
IPC_C2_DOMAIN="sh.azurestaticprovider.net"
IPC_C2_IP="37.16.75.69"

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  2a · Lockfile scan  (npm / pnpm / yarn / bun)  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

if [[ ${#LOCKFILES[@]} -eq 0 ]]; then
  info "No lockfiles found"
else
  for lf in "${LOCKFILES[@]}"; do
    lf_pm=$(basename "$lf")
    flagged=0

    if [[ "$lf_pm" == "bun.lockb" ]]; then
      bun_text=$(read_bun_lockfile "$lf")
      for ver in "${IPC_BAD_VERSIONS[@]}"; do
        if echo "$bun_text" | grep -qE "node-ipc.*${ver}|${ver}.*node-ipc"; then
          hit "MALICIOUS node-ipc@${ver} in bun.lockb"
          detail "File: $lf"
          flagged=1
        fi
      done
      echo "$bun_text" | grep -q "peacenotwar" && { hit "peacenotwar payload in bun.lockb: $lf"; flagged=1; }
      [[ $flagged -eq 0 ]] && ok "Clean [bun.lockb]: $(basename "$(dirname "$lf")")/bun.lockb"
      continue
    fi

    for ver in "${IPC_BAD_VERSIONS[@]}"; do
      if lockfile_has_pkg_ver "$lf" "node-ipc" "$ver"; then
        hit "MALICIOUS node-ipc@${ver} in [$lf_pm]"
        detail "File: $lf"
        flagged=1
      fi
    done

    grep -qF "peacenotwar" "$lf" 2>/dev/null && { hit "peacenotwar payload in [$lf_pm]: $lf"; flagged=1; }
    [[ $flagged -eq 0 ]] && ok "Clean [$lf_pm]: $(basename "$(dirname "$lf")")/$(basename "$lf")"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  2b · node_modules  —  installed version check  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

IPC_NM_ROOTS=("${SCAN_ROOTS[@]}")
if command -v pnpm &>/dev/null; then
  _ps=$(pnpm store path 2>/dev/null || true)
  [[ -n "$_ps" && -d "$_ps" ]] && IPC_NM_ROOTS+=("$_ps")
fi

progress "Searching node_modules/node-ipc"
ipc_nm_found=0
while IFS= read -r pkg_json; do
  [[ "$pkg_json" == *"node-ipc"* ]] || continue
  installed_ver=$(python3 -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('version',''))" 2>/dev/null)
  for ver in "${IPC_BAD_VERSIONS[@]}"; do
    if [[ "$installed_ver" == "$ver" ]]; then
      ipc_nm_found=1
      hit "MALICIOUS node-ipc@${ver} INSTALLED"
      detail "Path: $pkg_json"
      ipc_dir=$(dirname "$pkg_json")
      if [[ -f "${ipc_dir}/services/peacenotwar" || -d "${ipc_dir}/node_modules/peacenotwar" ]]; then
        hit "  peacenotwar payload CONFIRMED alongside node-ipc"
      fi
    fi
  done
done < <(
  find "${IPC_NM_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/node_modules/node-ipc/package.json" \
    -not -path "*/Library/CloudStorage/*" \
    -not -path "*/Library/Caches/*" \
    -not -path "*/.Trash/*" \
    2>/dev/null | head -300
)
[[ $ipc_nm_found -eq 0 ]] && ok "node-ipc: no malicious versions found in node_modules [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  2c · IOC file  —  node-ipc.cjs hash verification  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

cjs_found=0
while IFS= read -r cjs_file; do
  cjs_found=1
  actual=$(sha256 "$cjs_file")
  if [[ "$actual" == "$IPC_CJS_HASH" ]]; then
    hit "node-ipc.cjs HASH MATCHES KNOWN MALICIOUS FILE"
    detail "Path:    $cjs_file"
    detail "SHA-256: $actual  ← CONFIRMED MALICIOUS"
  else
    warn "node-ipc.cjs found (hash differs from known IOC — may be clean or different variant)"
    detail "Path:    $cjs_file"
    detail "SHA-256: $actual"
    detail "IOC ref: $IPC_CJS_HASH"
  fi
done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/node_modules/node-ipc/node-ipc.cjs" \
    -not -path "*/Library/CloudStorage/*" \
    2>/dev/null | head -50
)
[[ $cjs_found -eq 0 ]] && ok "node-ipc.cjs not found [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  2d · C2 / network IOC  —  sh.azurestaticprovider.net  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

# DNS history check — use mDNSResponder log (last 48h), NOT dscacheutil.
# dscacheutil -q host performs a live DNS lookup and populates the cache itself,
# making any subsequent cache check a false positive.
IPC_DNS_LOG=$(log show \
  --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "ANSWER"' \
  --last 48h 2>/dev/null | grep -v "^Filtering\|^Timestamp\|^[[:space:]]*$" || true)

if echo "$IPC_DNS_LOG" | grep -qiF "$IPC_C2_DOMAIN"; then
  hit "DNS history: this machine resolved the node-ipc C2 domain in the last 48h"
  detail "Domain: $IPC_C2_DOMAIN"
  echo "$IPC_DNS_LOG" | grep -iF "$IPC_C2_DOMAIN" | head -2 | \
    while IFS= read -r l; do detail "$l"; done
else
  ok "DNS history: $IPC_C2_DOMAIN — not resolved in last 48h"
fi

if echo "$IPC_DNS_LOG" | grep -qF "$IPC_C2_IP"; then
  hit "DNS history: C2 IP appeared in DNS answers in the last 48h"
  detail "IP: $IPC_C2_IP"
else
  ok "DNS history: $IPC_C2_IP — not seen in DNS answers in last 48h"
fi

# Active socket check (lsof by IP only — avoids DNS side-effect of lsof @domain)
if lsof -i "@${IPC_C2_IP}" -nP 2>/dev/null | grep -q .; then
  hit "ACTIVE socket to node-ipc C2 IP: $IPC_C2_IP"
  lsof -i "@${IPC_C2_IP}" -nP 2>/dev/null | tee -a "$LOGFILE"
else
  ok "No active connection to $IPC_C2_IP"
fi

# bt.node.js DNS exfil domain
if echo "$IPC_DNS_LOG" | grep -qiF "bt.node.js"; then
  hit "DNS exfil domain 'bt.node.js' found in DNS history — active data exfiltration indicator"
else
  ok "DNS history: bt.node.js — not resolved in last 48h"
fi

for pf_log in "/var/log/pf.log" "$HOME/Library/Logs/Little Snitch/Little Snitch Network Monitor.log"; do
  [[ -f "$pf_log" ]] || continue
  if grep -qE "azurestaticprovider|37\.16\.75\.69|bt\.node\.js" "$pf_log" 2>/dev/null; then
    hit "C2 contact in network log: $pf_log"
    grep -E "azurestaticprovider|37\.16\.75\.69|bt\.node\.js" "$pf_log" 2>/dev/null | \
      tail -5 | while IFS= read -r l; do detail "$l"; done || true
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  2e · Global packages  (npm / yarn / pnpm)  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

if command -v npm &>/dev/null; then
  g=$(npm list -g --depth=0 --json 2>/dev/null || echo '{}')
  for ver in "${IPC_BAD_VERSIONS[@]}"; do
    if echo "$g" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ipc=d.get('dependencies',{}).get('node-ipc',{})
print('yes' if ipc.get('version','')==sys.argv[1] else '',end='')
" "$ver" 2>/dev/null | grep -q yes; then
      hit "MALICIOUS node-ipc@${ver} installed GLOBALLY via npm"
    fi
  done
  echo "$g" | grep -qF '"peacenotwar"' && hit "peacenotwar installed globally via npm"
fi

if command -v yarn &>/dev/null; then
  yg=$(yarn global list --depth=0 2>/dev/null || true)
  for ver in "${IPC_BAD_VERSIONS[@]}"; do
    echo "$yg" | grep -qE "node-ipc@${ver}|node-ipc.*${ver}" && \
      hit "MALICIOUS node-ipc@${ver} installed GLOBALLY via yarn"
  done
fi

if command -v pnpm &>/dev/null; then
  pg=$(pnpm list -g --json 2>/dev/null || true)
  for ver in "${IPC_BAD_VERSIONS[@]}"; do
    if echo "$pg" | python3 -c "
import sys,json
try:
  pkgs=json.load(sys.stdin)
  if isinstance(pkgs,list): pkgs=pkgs[0] if pkgs else {}
  ipc=pkgs.get('dependencies',{}).get('node-ipc',{})
  print('yes' if ipc.get('version','')==sys.argv[1] else '',end='')
except: pass
" "$ver" 2>/dev/null | grep -q yes; then
      hit "MALICIOUS node-ipc@${ver} installed GLOBALLY via pnpm"
    fi
  done
fi
ok "Global package check complete [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
# 2f: Cache scan (skipped in fast mode — slow, low incremental value)
# ─────────────────────────────────────────────────────────────────────────────
if [[ $FAST_MODE -eq 0 ]]; then
  sep; banner "  2f · Package manager caches  [$(elapsed)]"
  _log ""

  NPM_CACHE=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")
  if [[ -d "$NPM_CACHE" ]]; then
    # Legacy tarballs
    while IFS= read -r tgz; do
      for ver in "${IPC_BAD_VERSIONS[@]}"; do
        [[ "$tgz" == *"node-ipc"*"${ver}"* ]] && \
          warn "Malicious node-ipc@${ver} tarball in npm cache: $tgz  → npm cache clean --force"
      done
    done < <(find "$NPM_CACHE" -name "*.tgz" -path "*node-ipc*" 2>/dev/null)

    # Content-addressable cache — grep for bad key strings, no heredoc-in-pipe
    while IFS= read -r idx; do
      for ver in "${IPC_BAD_VERSIONS[@]}"; do
        if grep -qF "node-ipc-${ver}" "$idx" 2>/dev/null || \
           grep -qF "node-ipc/${ver}" "$idx" 2>/dev/null; then
          warn "Malicious node-ipc@${ver} key in npm _cacache: $idx  → npm cache clean --force"
        fi
      done
    done < <(find "$NPM_CACHE/_cacache/index-v5" -type f 2>/dev/null | \
               xargs grep -l "node-ipc" 2>/dev/null | head -200)
  fi

  YARN_CACHE=$(yarn cache dir 2>/dev/null || echo "$HOME/.yarn/cache")
  for yc in "$YARN_CACHE" "$HOME/.yarn/cache" "$HOME/.cache/yarn"; do
    [[ -d "$yc" ]] || continue
    while IFS= read -r f; do
      for ver in "${IPC_BAD_VERSIONS[@]}"; do
        [[ "$f" == *"node-ipc"*"${ver}"* ]] && \
          warn "Malicious node-ipc@${ver} in yarn cache: $f  → yarn cache clean node-ipc"
      done
    done < <(find "$yc" \( -name "*.tgz" -o -name "*.zip" \) 2>/dev/null | grep "node-ipc" || true)
  done

  if command -v pnpm &>/dev/null; then
    PS=$(pnpm store path 2>/dev/null || true)
    if [[ -n "$PS" && -d "$PS" ]]; then
      while IFS= read -r pj; do
        sv=$(python3 -c "import json; d=json.load(open('$pj',errors='replace')); print(d.get('version',''))" 2>/dev/null)
        for ver in "${IPC_BAD_VERSIONS[@]}"; do
          [[ "$sv" == "$ver" ]] && \
            hit "MALICIOUS node-ipc@${ver} in pnpm content store: $pj  → pnpm store prune"
        done
      done < <(find "$PS" -path "*/node-ipc/package.json" 2>/dev/null | head -100)
    fi
  fi
  ok "Cache scan complete [$(elapsed)]"
else
  info "2f · Cache scan — skipped in fast mode"
fi

# ── Section 2 summary ─────────────────────────────────────────────────────────
SEC2_HITS=$SEC_HITS; SEC2_WARNS=$SEC_WARNS
_log ""
if   [[ $SEC_HITS  -gt 0 ]]; then
  _log "  ${BR}◉ Section 2 result: ${SEC_HITS} HIT(s) · ${SEC_WARNS} warning(s) — CRITICAL  [$(elapsed)]${NC}"
  _log "  ${R}  → DISCONNECT from network if C2 connection was found in 2d${NC}"
  _log "  ${R}  → Rotate SSH keys, AWS credentials, npm tokens, GitHub PATs IMMEDIATELY${NC}"
  _log "  ${R}  → npm uninstall node-ipc && npm cache clean --force${NC}"
  _log "  ${R}  → Upgrade node-ipc to 10.1.0+ (first clean release)${NC}"
elif [[ $SEC_WARNS -gt 0 ]]; then
  _log "  ${Y}⚠ Section 2 result: 0 confirmed hits · ${SEC_WARNS} warning(s)  [$(elapsed)]${NC}"
else
  _log "  ${BG}✔ Section 2 result: CLEAN — malicious node-ipc versions not detected  [$(elapsed)]${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2
banner "SECTION 3  —  Axios  (1.14.1 / 0.30.4 + plain-crypto-js injection)  [$(elapsed)]"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}Malicious: axios@1.14.1 (latest channel) and axios@0.30.4 (legacy channel).${NC}"
_log "  ${DIM}Both inject plain-crypto-js@4.2.1 for credential harvesting.${NC}"
_log ""

AXIOS_BAD_VERSIONS=("1.14.1" "0.30.4")
AXIOS_PAYLOAD="plain-crypto-js"

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  3a · Lockfile scan  (npm / pnpm / yarn / bun)  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""

if [[ ${#LOCKFILES[@]} -eq 0 ]]; then
  info "No lockfiles found"
else
  for lf in "${LOCKFILES[@]}"; do
    lf_pm=$(basename "$lf")
    flagged=0

    if [[ "$lf_pm" == "bun.lockb" ]]; then
      bun_text=$(read_bun_lockfile "$lf")
      for ver in "${AXIOS_BAD_VERSIONS[@]}"; do
        echo "$bun_text" | grep -qE "axios.*${ver}|${ver}.*axios" && \
          { hit "MALICIOUS axios@${ver} in bun.lockb: $lf"; flagged=1; }
      done
      echo "$bun_text" | grep -q "$AXIOS_PAYLOAD" && \
        { hit "plain-crypto-js payload in bun.lockb: $lf"; flagged=1; }
      [[ $flagged -eq 0 ]] && ok "Clean [bun.lockb]: $(basename "$(dirname "$lf")")/bun.lockb"
      continue
    fi

    for ver in "${AXIOS_BAD_VERSIONS[@]}"; do
      if lockfile_has_pkg_ver "$lf" "axios" "$ver"; then
        hit "MALICIOUS axios@${ver} in [$lf_pm]"
        detail "File: $lf"
        flagged=1
      fi
    done

    grep -qF "$AXIOS_PAYLOAD" "$lf" 2>/dev/null && \
      { hit "plain-crypto-js payload package in [$lf_pm]: $lf"; flagged=1; }

    all_axios=$(lockfile_pkg_versions "$lf" "axios")
    if [[ -n "$all_axios" ]]; then
      while IFS= read -r av; do
        [[ -z "$av" ]] && continue
        already_bad=0
        for bver in "${AXIOS_BAD_VERSIONS[@]}"; do [[ "$av" == "$bver" ]] && already_bad=1; done
        if [[ $already_bad -eq 0 ]]; then
          warn "axios@${av} in [$lf_pm] — verify this is not a compromised version"
          detail "File:        $lf"
          detail "Package:     axios@${av}"
          detail "Warn type:   Version not in known-bad list (1.14.1 / 0.30.4) — publish date unverified"
          detail "Action:      Run: npm view axios@${av} time"
          detail "             IGNORE if publish date is NOT between 2026-05-10 and 2026-05-14"
          detail "             ESCALATE (treat as HIT) if date falls within that window"
        fi
      done <<< "$all_axios"
    fi

    [[ $flagged -eq 0 ]] && ok "Clean [$lf_pm]: $(basename "$(dirname "$lf")")/$(basename "$lf")"
  done
fi

# ─────────────────────────────────────────────────────────────────────────────
sep; banner "  3b · node_modules  —  axios version + plain-crypto-js  [$(elapsed)]"
# ─────────────────────────────────────────────────────────────────────────────
_log ""
progress "Searching node_modules/axios"

ax_hits=0
while IFS= read -r pkg_json; do
  ax_ver=$(python3 -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('version',''))" 2>/dev/null)
  ax_date=$(file_date "$pkg_json")
  ax_dir=$(dirname "$pkg_json")

  for ver in "${AXIOS_BAD_VERSIONS[@]}"; do
    if [[ "$ax_ver" == "$ver" ]]; then
      hit "MALICIOUS axios@${ver} INSTALLED"
      detail "Path:      $pkg_json"
      detail "Installed: $ax_date"
      ax_hits=$((ax_hits+1))
      if [[ -d "${ax_dir}/node_modules/plain-crypto-js" ]] || \
         [[ -d "${ax_dir}/../plain-crypto-js" ]]; then
        hit "  plain-crypto-js payload CONFIRMED alongside malicious axios"
      fi
    fi
  done

  if in_risk_window "$ax_date"; then
    warn "axios installed/updated DURING risk window ($ax_date): ${ax_ver}"
    detail "File:        $pkg_json"
    detail "Package:     axios@${ax_ver}"
    detail "Installed:   $ax_date"
    detail "Warn type:   Install date falls in compromise window (2026-05-10 to 2026-05-14)"
    detail "Action:      Run: npm view axios@${ax_ver} time  — check if publish date matches"
    detail "             If axios@${ax_ver} is NOT 1.14.1 or 0.30.4, this is likely a false positive"
    detail "             ESCALATE only if version is 1.14.1 or 0.30.4"
  fi
done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/node_modules/axios/package.json" \
    -not -path "*/Library/CloudStorage/*" \
    -not -path "*/Library/Caches/*" \
    -not -path "*/.Trash/*" \
    2>/dev/null | head -200
)

pcjs_found=0
while IFS= read -r pkg_json; do
  pcjs_found=1
  pcjs_ver=$(python3 -c "import json; d=json.load(open('$pkg_json',errors='replace')); print(d.get('version','?'))" 2>/dev/null)
  hit "plain-crypto-js PAYLOAD INSTALLED: version ${pcjs_ver}"
  detail "Path: $pkg_json"
  detail "This package is exclusively a malicious payload — it has no legitimate use"
done < <(
  find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
    -path "*/node_modules/plain-crypto-js/package.json" \
    -not -path "*/Library/CloudStorage/*" \
    2>/dev/null | head -50
)
[[ $ax_hits -eq 0 && $pcjs_found -eq 0 ]] && ok "No malicious axios or plain-crypto-js in node_modules [$(elapsed)]"

# ─────────────────────────────────────────────────────────────────────────────
# 3c: package.json plain-crypto-js audit (skipped in fast mode)
# ─────────────────────────────────────────────────────────────────────────────
if [[ $FAST_MODE -eq 0 ]]; then
  sep; banner "  3c · package.json audit  —  plain-crypto-js in any dependency field  [$(elapsed)]"
  _log ""
  progress "Scanning package.json files"

  pj_hits=0
  while IFS= read -r pj; do
    [[ "$pj" == *"node_modules"* ]] && continue
    if grep -qF "plain-crypto-js" "$pj" 2>/dev/null; then
      hit "plain-crypto-js in package.json: $pj"
      grep -n "plain-crypto-js" "$pj" 2>/dev/null | \
        while IFS= read -r l; do detail "$l"; done || true
      pj_hits=$((pj_hits+1))
    fi
  done < <(
    find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
      -name "package.json" \
      -not -path "*/node_modules/*" \
      -not -path "*/.git/*" \
      -not -path "*/Library/CloudStorage/*" \
      2>/dev/null | head -500
  )
  [[ $pj_hits -eq 0 ]] && ok "package.json audit complete — plain-crypto-js not found [$(elapsed)]"

  # ─────────────────────────────────────────────────────────────────────────
  sep; banner "  3d · Source injection check  —  suspicious code inside axios dist  [$(elapsed)]"
  # ─────────────────────────────────────────────────────────────────────────
  _log ""
  _log "  ${DIM}Malicious axios builds inject credential harvesting code into axios/lib/ files${NC}"
  _log ""
  progress "Scanning axios source files"

  src_hits=0
  while IFS= read -r axios_lib; do
    # Only match actual malicious payload indicators — NOT standard browser APIs.
    # btoa/atob, document.cookie, localStorage are legitimate in every axios release.
    # plain.crypto / plain_crypto / CryptoJS are injected by the compromised builds only.
    if grep -qiE '(plain[._-]crypto|plain_crypto|CryptoJS\.enc\.|CryptoJS\.AES\.|require\(["\x27]plain-crypto|from\s+["\x27]plain-crypto)' \
       "$axios_lib" 2>/dev/null; then
      hit "Malicious payload code detected in axios source: $axios_lib"
      grep -nmiE '(plain[._-]crypto|plain_crypto|CryptoJS\.enc\.|CryptoJS\.AES\.|require\(["\x27]plain-crypto|from\s+["\x27]plain-crypto)' \
        "$axios_lib" 2>/dev/null | head -5 | \
        while IFS= read -r l; do detail "$l"; done || true
      src_hits=$((src_hits+1))
    fi
  done < <(
    find "${SCAN_ROOTS[@]}" -maxdepth $MAXDEPTH \
      \( -path "*/node_modules/axios/lib/*.js" -o \
         -path "*/node_modules/axios/dist/*.js" \) \
      -not -path "*/Library/CloudStorage/*" \
      2>/dev/null | head -100
  )
  [[ $src_hits -eq 0 ]] && ok "axios source injection check complete — clean [$(elapsed)]"
else
  info "3c · package.json audit — skipped in fast mode"
  info "3d · Source injection check — skipped in fast mode"
fi

# ── Section 3 summary ─────────────────────────────────────────────────────────
SEC3_HITS=$SEC_HITS; SEC3_WARNS=$SEC_WARNS
_log ""
if   [[ $SEC_HITS  -gt 0 ]]; then
  _log "  ${BR}◉ Section 3 result: ${SEC_HITS} HIT(s) · ${SEC_WARNS} warning(s) — ACTION REQUIRED  [$(elapsed)]${NC}"
  _log "  ${R}  → npm uninstall axios plain-crypto-js${NC}"
  _log "  ${R}  → Reinstall axios from a known-clean version (e.g., axios@1.7.9)${NC}"
  _log "  ${R}  → Rotate any credentials loaded by your frontend/backend${NC}"
elif [[ $SEC_WARNS -gt 0 ]]; then
  _log "  ${Y}⚠ Section 3 result: 0 confirmed hits · ${SEC_WARNS} warning(s) — verify axios version  [$(elapsed)]${NC}"
else
  _log "  ${BG}✔ Section 3 result: CLEAN — no malicious axios or plain-crypto-js detected  [$(elapsed)]${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
sep2
banner "FINAL SUMMARY  [$(elapsed) total]"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""

GRAND_HITS=$((SEC1_HITS + SEC2_HITS + SEC3_HITS))
GRAND_WARNS=$((SEC1_WARNS + SEC2_WARNS + SEC3_WARNS))
TOTAL_ELAPSED=$((SECONDS - SCAN_START))

_log "  ${BOLD}Scan completed:  $(date)${NC}"
_log "  ${BOLD}Mode:            ${SCAN_MODE}${NC}"
_log "  ${BOLD}Elapsed:         ${TOTAL_ELAPSED}s${NC}"
_log "  ${BOLD}Lockfiles found: ${#LOCKFILES[@]}${NC}"
_log ""
_log "  ${BOLD}${W}┌───────────────────────────────────────────────────┐${NC}"
_log "  ${BOLD}${W}│  VULNERABILITY              HITS    WARNS          │${NC}"
_log "  ${BOLD}${W}├───────────────────────────────────────────────────┤${NC}"

if [[ $SEC1_HITS -gt 0 ]]; then
  _log "  ${BOLD}${R}│  TanStack CVE-2026-45321    ${SEC1_HITS}       ${SEC1_WARNS}                │${NC}"
else
  _log "  ${BOLD}${G}│  TanStack CVE-2026-45321    ${SEC1_HITS}       ${SEC1_WARNS}                │${NC}"
fi

if [[ $SEC2_HITS -gt 0 ]]; then
  _log "  ${BOLD}${R}│  node-ipc backdoor          ${SEC2_HITS}       ${SEC2_WARNS}                │${NC}"
else
  _log "  ${BOLD}${G}│  node-ipc backdoor          ${SEC2_HITS}       ${SEC2_WARNS}                │${NC}"
fi

if [[ $SEC3_HITS -gt 0 ]]; then
  _log "  ${BOLD}${R}│  Axios compromise           ${SEC3_HITS}       ${SEC3_WARNS}                │${NC}"
else
  _log "  ${BOLD}${G}│  Axios compromise           ${SEC3_HITS}       ${SEC3_WARNS}                │${NC}"
fi

_log "  ${BOLD}${W}├───────────────────────────────────────────────────┤${NC}"
_log "  ${BOLD}${W}│  TOTAL                      ${GRAND_HITS}       ${GRAND_WARNS}                │${NC}"
_log "  ${BOLD}${W}└───────────────────────────────────────────────────┘${NC}"
_log ""

if [[ $GRAND_HITS -gt 0 ]]; then
  _log "  ${BR}${BOLD}⚠  ${GRAND_HITS} confirmed hit(s) require immediate action — see sections above${NC}"
elif [[ $GRAND_WARNS -gt 0 ]]; then
  _log "  ${BY}${BOLD}⚠  No confirmed hits — ${GRAND_WARNS} package(s) require manual version verification${NC}"
  _log ""
  _log "  ${Y}  To verify a TanStack version:  npm view @tanstack/<pkg>@<ver> time${NC}"
  _log "  ${Y}  To verify an axios version:    npm view axios@<ver> time${NC}"
else
  _log "  ${BG}${BOLD}✔  CLEAN — no malicious packages detected across all three vulnerability classes${NC}"
fi

_log ""
_log "  ${DIM}Full log: $LOGFILE${NC}"
_log ""
