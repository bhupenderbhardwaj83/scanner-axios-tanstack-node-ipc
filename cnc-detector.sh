#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  cnc-detector.sh  —  C2 / CnC Communication Detector  v1.1 By Design Engineer - Network18
#
#  Detects active and historical command-and-control traffic from:
#    ① TanStack CVE-2026-45321   (router_init.js / tanstack_runner.js payload)
#    ② node-ipc backdoor         (9.1.6 / 9.2.3 / 12.0.1)
#    ③ Axios + plain-crypto-js   (1.14.1 / 0.30.4 credential harvester)
#
#  Checks:
#    • DNS cache   — recently resolved C2 domains (no network needed)
#    • Live sockets — active/established connections to C2 infrastructure
#    • Node processes — outbound connections made by node/npm processes
#    • /etc/hosts  — DNS hijacking / C2 domain overrides
#    • DNS resolver — /etc/resolv.conf tampering (node-ipc redirects DNS)
#    • Unified log  — historical evidence in macOS system logs (last 48h)
#    • Network logs — pf.log / Little Snitch / mDNSResponder
#    • LaunchAgents — persistence beacons installed by payloads
#    • Cron jobs    — scheduled exfiltration tasks
#    • Env vars     — suspicious URLs in running node process environments
#    • Block status — passive check of pf/hosts/Little Snitch C2 blocks
#
#  Safe: read-only, no changes made, runs without root for most checks
#  Time: ~30-60 seconds
# ══════════════════════════════════════════════════════════════════════════════
set -eo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m';  BR='\033[1;31m'
Y='\033[1;33m';  BY='\033[1;93m'
G='\033[0;32m';  BG='\033[1;32m'
C='\033[0;36m';  BC='\033[1;36m'
M='\033[0;35m';
W='\033[1;37m';  DIM='\033[2m'
BOLD='\033[1m';  NC='\033[0m'

# ── Log ───────────────────────────────────────────────────────────────────────
LOGFILE="$(pwd)/cnc_detect_$(date +%Y%m%d_%H%M%S).log"
_log()   { echo -e "$*" | tee -a "$LOGFILE"; }
sep()    { _log "${DIM}  ────────────────────────────────────────────────────────${NC}"; }
sep2()   { _log "\n${BOLD}${W}══════════════════════════════════════════════════════════${NC}"; }
banner() { _log "\n${BOLD}${BC}$*${NC}"; }
hit()    { HITS=$((HITS+1));   SEC_HITS=$((SEC_HITS+1));   _log "${BR}  ◉ [C2 HIT]  ${NC}${R}$*${NC}"; }
warn()   { WARNS=$((WARNS+1)); SEC_WARNS=$((SEC_WARNS+1)); _log "${Y}  ⚠ [SUSPECT] ${NC}$*"; }
ok()     { _log "${BG}  ✔ [CLEAN]   ${NC}${G}$*${NC}"; }
info()   { _log "${C}  ℹ [INFO]    ${NC}$*"; }
detail() { _log "${DIM}              $*${NC}"; }
phase()  { _log "\n${BOLD}${M}  ▶ $*${NC}  ${DIM}[${SECONDS}s]${NC}"; }

HITS=0; WARNS=0; SCAN_START=$SECONDS
elapsed() { printf "%ds" "$((SECONDS - SCAN_START))"; }

# ── Known C2 IOCs ─────────────────────────────────────────────────────────────

# node-ipc backdoor
IPC_C2_DOMAINS=("sh.azurestaticprovider.net" "bt.node.js")
IPC_C2_IPS=("37.16.75.69")

# TanStack CVE-2026-45321
# router_init.js / tanstack_runner.js payloads phone home to:
TS_C2_DOMAINS=(
  "cdn-tanstack-router.vercel-dns.com"
  "tanstack-telemetry.workers.dev"
  "router-analytics.tanstack-cdn.com"
  "npm-telemetry.tanstack-infra.net"
)
TS_C2_IPS=("185.220.101.47" "104.21.96.1")

# Axios / plain-crypto-js credential harvester
AX_C2_DOMAINS=(
  "plain-crypto.vercel.app"
  "analytics.plain-crypto.com"
  "api.cryptojs-cdn.net"
  "data-collect.axios-cdn.workers.dev"
)
AX_C2_IPS=("78.46.92.33" "95.216.147.234")

# Combined lists for joint checks
ALL_C2_DOMAINS=("${IPC_C2_DOMAINS[@]}" "${TS_C2_DOMAINS[@]}" "${AX_C2_DOMAINS[@]}")
ALL_C2_IPS=("${IPC_C2_IPS[@]}" "${TS_C2_IPS[@]}" "${AX_C2_IPS[@]}")

# Suspicious keywords that appear in C2 traffic / payload code
C2_KEYWORDS=(
  "azurestaticprovider"
  "plain-crypto"
  "tanstack-telemetry"
  "tanstack-cdn"
  "peacenotwar"
  "cryptojs-cdn"
  "bt.node.js"
  "npm-telemetry"
  "router-analytics"
  "data-collect.axios"
)

# ─────────────────────────────────────────────────────────────────────────────
clear
_log ""
_log "${BOLD}${BC}╔══════════════════════════════════════════════════════════════╗${NC}"
_log "${BOLD}${BC}║   C2 / CnC Communication Detector  ·  v1.0                  ║${NC}"
_log "${BOLD}${BC}║   TanStack CVE-2026-45321  ·  node-ipc  ·  Axios            ║${NC}"
_log "${BOLD}${BC}╚══════════════════════════════════════════════════════════════╝${NC}"
_log ""
_log "  ${DIM}Log → $LOGFILE${NC}"
_log "  ${DIM}$(date)${NC}"
_log "  ${DIM}Host: $(hostname)  |  User: $(whoami)${NC}"
_log ""

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 1  —  DNS Cache  (recently resolved C2 domains)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}DNS cache shows domains this machine has looked up recently.${NC}"
_log "  ${DIM}A cache hit means malicious code already ran and called home.${NC}"
_log ""
phase "Checking DNS history via .tracev3 log files (fast string scan — no log show)"
# log show reads /private/var/db/diagnostics/Persist/*.tracev3 (500 MB+).
# Scanning ALL of them is why Phase 5 hangs.
# Strategy: use `strings` on only the .tracev3 files modified in the last 24h —
# orders of magnitude faster; C2 domain strings survive compression as plaintext.

TRACEV3_DIR="/private/var/db/diagnostics"
dns_cache_hit=0
mdns_hit=0

# Collect recent tracev3 files (last 24h, across all subdirs)
RECENT_LOGS=$(find "$TRACEV3_DIR" -name "*.tracev3" -newer "$(date -v-24H +%Y%m%d%H%M%S 2>/dev/null || date --date='24 hours ago' +%Y%m%d%H%M%S)" \
  2>/dev/null | head -60 || true)

if [[ -z "$RECENT_LOGS" ]]; then
  # Fallback: just use last-modified files in Persist/
  RECENT_LOGS=$(ls -t "$TRACEV3_DIR/Persist/"*.tracev3 2>/dev/null | head -20 || true)
fi

if [[ -n "$RECENT_LOGS" ]]; then
  file_count=$(echo "$RECENT_LOGS" | wc -l | tr -d ' ')
  detail "Scanning $file_count recent .tracev3 file(s) in $TRACEV3_DIR"

  # Run strings on all recent files at once — fast binary text extraction
  STRINGS_OUT=$(echo "$RECENT_LOGS" | xargs strings 2>/dev/null || true)

  for domain in "${ALL_C2_DOMAINS[@]}"; do
    if echo "$STRINGS_OUT" | grep -qiF "$domain"; then
      count=$(echo "$STRINGS_OUT" | grep -icF "$domain" || echo "?")
      hit "C2 domain string found in system log files (last 24h): $domain  [$count occurrence(s)]"
      dns_cache_hit=1; mdns_hit=1
    fi
  done

  for ip in "${ALL_C2_IPS[@]}"; do
    if echo "$STRINGS_OUT" | grep -qF "$ip"; then
      count=$(echo "$STRINGS_OUT" | grep -cF "$ip" || echo "?")
      hit "C2 IP string found in system log files (last 24h): $ip  [$count occurrence(s)]"
      dns_cache_hit=1; mdns_hit=1
    fi
  done
else
  info "No recent .tracev3 files accessible (may need sudo for /private/var/db/diagnostics)"
fi

[[ $dns_cache_hit -eq 0 ]] && ok "DNS log: no C2 domains or IPs found in recent system log files"

S1_HITS=$SEC_HITS; S1_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 2  —  Live Sockets  (active connections RIGHT NOW)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}Checks open TCP/UDP sockets against all known C2 IPs and domains.${NC}"
_log "  ${DIM}ESTABLISHED = data is actively flowing. CLOSE_WAIT = recent connection.${NC}"
_log ""
phase "Scanning all open network connections via lsof"

lsof_output=$(lsof -i -n -P 2>/dev/null || true)
lsof_named=$(lsof -i -P 2>/dev/null || true)   # with hostname resolution

live_hit=0
for ip in "${ALL_C2_IPS[@]}"; do
  matches=$(echo "$lsof_output" | grep "$ip" || true)
  if [[ -n "$matches" ]]; then
    hit "LIVE CONNECTION to C2 IP: $ip"
    echo "$matches" | while IFS= read -r l; do detail "$l"; done
    live_hit=1
  fi
done

for domain in "${ALL_C2_DOMAINS[@]}"; do
  matches=$(echo "$lsof_named" | grep "$domain" || true)
  if [[ -n "$matches" ]]; then
    hit "LIVE CONNECTION to C2 domain: $domain"
    echo "$matches" | while IFS= read -r l; do detail "$l"; done
    live_hit=1
  fi
done

# Check keyword patterns in raw lsof output
for kw in "azurestaticprovider" "plain-crypto" "tanstack-telemetry" "bt.node.js"; do
  matches=$(echo "$lsof_named" | grep -i "$kw" || true)
  if [[ -n "$matches" ]]; then
    hit "LIVE CONNECTION matching C2 keyword: $kw"
    echo "$matches" | while IFS= read -r l; do detail "$l"; done
    live_hit=1
  fi
done

[[ $live_hit -eq 0 ]] && ok "lsof: no live connections to any known C2 endpoint"

phase "Checking via netstat for ESTABLISHED/CLOSE_WAIT to C2 IPs"
netstat_output=$(netstat -an 2>/dev/null || true)
ns_hit=0
for ip in "${ALL_C2_IPS[@]}"; do
  matches=$(echo "$netstat_output" | grep -E "ESTABLISHED|CLOSE_WAIT" | grep "$ip" || true)
  if [[ -n "$matches" ]]; then
    hit "netstat: connection to C2 IP $ip"
    echo "$matches" | while IFS= read -r l; do detail "$l"; done
    ns_hit=1
  fi
done
[[ $ns_hit -eq 0 ]] && ok "netstat: no ESTABLISHED/CLOSE_WAIT connections to C2 IPs"

S2_HITS=$SEC_HITS; S2_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 3  —  Node.js Process Forensics  (what are node processes doing?)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}Identifies all running node/npm/npx processes and their open connections.${NC}"
_log "  ${DIM}Malicious payloads run inside node, so node's network activity is the signal.${NC}"
_log ""
phase "Enumerating node/npm/npx/bun processes"

node_pids=$(pgrep -x "node" 2>/dev/null || pgrep -f "node " 2>/dev/null || true)
npm_pids=$(pgrep -f "npm " 2>/dev/null || true)
bun_pids=$(pgrep -x "bun" 2>/dev/null || true)
all_node_pids=$(echo "$node_pids $npm_pids $bun_pids" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u || true)

if [[ -z "$all_node_pids" ]]; then
  ok "No node/npm/bun processes currently running"
else
  proc_count=$(echo "$all_node_pids" | wc -l | tr -d ' ')
  info "Found $proc_count node-family process(es)"

  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue

    cmd=$(ps -p "$pid" -o comm= 2>/dev/null || echo "?")
    args=$(ps -p "$pid" -o args= 2>/dev/null | cut -c1-120 || echo "?")
    _log ""
    _log "  ${BOLD}PID $pid${NC}  ${DIM}($cmd)${NC}"
    detail "Command: $args"

    # Open connections for this PID
    proc_conns=$(lsof -i -n -P -p "$pid" 2>/dev/null | grep -E "ESTABLISHED|LISTEN|UDP" || true)
    if [[ -n "$proc_conns" ]]; then
      detail "Network:"
      echo "$proc_conns" | while IFS= read -r l; do detail "  $l"; done

      # Check if any connection goes to a C2 IP
      for ip in "${ALL_C2_IPS[@]}"; do
        echo "$proc_conns" | grep -q "$ip" && \
          hit "PID $pid ($cmd) has ACTIVE connection to C2 IP: $ip"
      done
      # Check for unusual outbound ports used by exfil (4444, 8080 to unknown, raw 443)
      suspicious_ports=$(echo "$proc_conns" | grep -E "ESTABLISHED" | \
        grep -vE ":(443|80|8080|3000|5432|6379|27017|5173)\s" | \
        grep -vE "127\.0\.0\.1|::1|\[::1\]" | head -10 || true)
      if [[ -n "$suspicious_ports" ]]; then
        warn "PID $pid ($cmd) has established connection on unusual port"
        echo "$suspicious_ports" | while IFS= read -r l; do detail "  $l"; done
      fi
    fi

    # Environment variables — look for C2 domains/URLs embedded in env
    # NOTE: do NOT grep for short tokens like "C2" — they match hashes/keys (false positive)
    # Only match full C2 domain strings or unambiguous payload names
    env_vars=$(ps eww -p "$pid" 2>/dev/null | tr ' ' '\n' | \
      grep -iE "(azurestaticprovider\.net|plain-crypto\.(vercel|com)|tanstack-telemetry\.|tanstack-cdn\.|peacenotwar|bt\.node\.js|cryptojs-cdn\.|npm-telemetry\.|router-analytics\.|data-collect\.axios)" || true)
    if [[ -n "$env_vars" ]]; then
      hit "PID $pid ($cmd) has C2 domain in environment variable"
      echo "$env_vars" | while IFS= read -r l; do detail "  $l"; done
    fi
  done <<< "$all_node_pids"
fi

S3_HITS=$SEC_HITS; S3_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 4  —  DNS & Host Integrity  (/etc/hosts · /etc/resolv.conf)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}node-ipc payload overrides DNS resolvers to bypass corporate filtering.${NC}"
_log "  ${DIM}Plain-crypto-js has been observed adding C2 entries to /etc/hosts.${NC}"
_log ""
phase "Scanning /etc/hosts for C2 domain entries"

hosts_hit=0
for domain in "${ALL_C2_DOMAINS[@]}"; do
  match=$(grep -i "$domain" /etc/hosts 2>/dev/null || true)
  if [[ -n "$match" ]]; then
    hit "/etc/hosts contains C2 domain: $domain"
    detail "$match"
    hosts_hit=1
  fi
done

# Also look for any hosts pointing to known C2 IPs
for ip in "${ALL_C2_IPS[@]}"; do
  match=$(grep "$ip" /etc/hosts 2>/dev/null || true)
  if [[ -n "$match" ]]; then
    hit "/etc/hosts contains C2 IP: $ip"
    detail "$match"
    hosts_hit=1
  fi
done

# Flag suspicious hosts file additions (any non-local non-comment entry could be injected)
suspicious_hosts=$(grep -vE "^#|^$|127\.|^::1|^fe80|^ff" /etc/hosts 2>/dev/null | \
  grep -vE "^0\.0\.0\.0\s+(0\.0\.0\.0|broadcasthost)" | \
  grep -vE "^255\.255\.255\.255\s+broadcasthost" || true)
if [[ -n "$suspicious_hosts" ]]; then
  warn "/etc/hosts has non-standard entries — review manually"
  echo "$suspicious_hosts" | while IFS= read -r l; do detail "$l"; done
fi
[[ $hosts_hit -eq 0 ]] && ok "/etc/hosts: no C2 domain or IP entries found"

phase "Checking DNS resolver configuration (/etc/resolv.conf)"
if [[ -f /etc/resolv.conf ]]; then
  resolv=$(cat /etc/resolv.conf 2>/dev/null)
  # node-ipc redirects to 8.8.8.8 / 1.1.1.1 to bypass corporate resolver
  if echo "$resolv" | grep -qE "nameserver\s+(8\.8\.8\.8|1\.1\.1\.1|8\.8\.4\.4)"; then
    warn "/etc/resolv.conf uses public DNS (Google/Cloudflare) — node-ipc payload forces this to bypass corporate DNS monitoring"
    echo "$resolv" | grep "nameserver" | while IFS= read -r l; do detail "$l"; done
  else
    ok "/etc/resolv.conf: DNS resolver appears standard"
  fi
fi

phase "Checking macOS DNS settings via scutil"
scutil_dns=$(scutil --dns 2>/dev/null | grep -E "nameserver\[" | awk '{print $3}' | sort -u || true)
if [[ -n "$scutil_dns" ]]; then
  info "Active DNS resolvers:"
  echo "$scutil_dns" | while IFS= read -r ns; do
    if echo "$ns" | grep -qE "^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1)$"; then
      warn "Public DNS resolver active: $ns — expected if on home network; suspicious on corporate network"
    else
      detail "  Resolver: $ns"
    fi
  done
fi

S4_HITS=$SEC_HITS; S4_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 5  —  System Log Analysis  (last 48h of macOS unified log)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}macOS unified log captures all process activity including network syscalls.${NC}"
_log "  ${DIM}Evidence of past C2 contact survives process termination.${NC}"
_log ""
phase "Scanning recent .tracev3 files for C2 keywords (fast strings pass)"
# Reuse STRINGS_OUT from Phase 1 scan above — no second filesystem pass needed.
# If Phase 1 ran, STRINGS_OUT is already populated. If not (no recent files), skip.

ulog_hit=0
if [[ -n "${STRINGS_OUT:-}" ]]; then
  for kw in "${C2_KEYWORDS[@]}"; do
    if echo "$STRINGS_OUT" | grep -qiF "$kw"; then
      count=$(echo "$STRINGS_OUT" | grep -icF "$kw" || echo "?")
      hit "C2 keyword found in system log files: \"$kw\"  [$count occurrence(s)]"
      ulog_hit=1
    fi
  done
  [[ $ulog_hit -eq 0 ]] && ok "System log files: no C2 keywords found in recent .tracev3 files"
else
  info "Skipping keyword scan — no .tracev3 files were accessible"
fi

phase "Checking network-related log files"

# pf firewall log
if [[ -f /var/log/pf.log ]]; then
  pf_hit=0
  for kw in "${C2_KEYWORDS[@]}"; do
    match=$(grep -i "$kw" /var/log/pf.log 2>/dev/null | tail -5 || true)
    if [[ -n "$match" ]]; then
      hit "pf.log: C2 keyword found: $kw"
      echo "$match" | while IFS= read -r l; do detail "$l"; done
      pf_hit=1
    fi
  done
  for ip in "${ALL_C2_IPS[@]}"; do
    match=$(grep "$ip" /var/log/pf.log 2>/dev/null | tail -5 || true)
    if [[ -n "$match" ]]; then
      hit "pf.log: C2 IP traffic: $ip"
      echo "$match" | while IFS= read -r l; do detail "$l"; done
      pf_hit=1
    fi
  done
  [[ $pf_hit -eq 0 ]] && ok "pf.log: no C2 traffic found"
else
  info "pf.log not found (pf firewall may not be active)"
fi

# Little Snitch
LS_LOG="$HOME/Library/Logs/Little Snitch/Little Snitch Network Monitor.log"
if [[ -f "$LS_LOG" ]]; then
  ls_hit=0
  for kw in "${C2_KEYWORDS[@]}"; do
    match=$(grep -i "$kw" "$LS_LOG" 2>/dev/null | tail -5 || true)
    if [[ -n "$match" ]]; then
      hit "Little Snitch log: C2 keyword: $kw"
      echo "$match" | while IFS= read -r l; do detail "$l"; done
      ls_hit=1
    fi
  done
  for ip in "${ALL_C2_IPS[@]}"; do
    match=$(grep "$ip" "$LS_LOG" 2>/dev/null | tail -5 || true)
    if [[ -n "$match" ]]; then
      hit "Little Snitch log: C2 IP: $ip"
      echo "$match" | while IFS= read -r l; do detail "$l"; done
      ls_hit=1
    fi
  done
  [[ $ls_hit -eq 0 ]] && ok "Little Snitch log: no C2 traffic found"
else
  info "Little Snitch log not found (not installed)"
fi

S5_HITS=$SEC_HITS; S5_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 6  —  Persistence Mechanisms  (LaunchAgents · Cron · Login Items)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}Malicious payloads install LaunchAgents or cron jobs to beacon persistently.${NC}"
_log "  ${DIM}These survive reboots and re-establish C2 even after package removal.${NC}"
_log ""
phase "Scanning LaunchAgents and LaunchDaemons"

LAUNCH_DIRS=(
  "$HOME/Library/LaunchAgents"
  "/Library/LaunchAgents"
  "/Library/LaunchDaemons"
  "/System/Library/LaunchAgents"
)

persist_hit=0
for ldir in "${LAUNCH_DIRS[@]}"; do
  [[ -d "$ldir" ]] || continue
  while IFS= read -r plist; do
    # Check each plist for C2 keywords and suspicious patterns
    content=$(cat "$plist" 2>/dev/null || true)

    for kw in "${C2_KEYWORDS[@]}"; do
      if echo "$content" | grep -qi "$kw"; then
        hit "LaunchAgent/Daemon contains C2 keyword: $kw"
        detail "File: $plist"
        persist_hit=1
      fi
    done

    # Suspicious: plist with curl/wget + external URL
    if echo "$content" | grep -qiE "(curl|wget)\s+https?://" && \
       ! echo "$content" | grep -qiE "apple\.com|icloud\.com|me\.com"; then
      warn "LaunchAgent/Daemon with external curl/wget: $plist"
      echo "$content" | grep -iE "(curl|wget)" | head -3 | \
        while IFS= read -r l; do detail "  $l"; done
      persist_hit=1
    fi

    # Suspicious: plist running node with inline eval or -e flag
    if echo "$content" | grep -qiE "node\s+-e|node\s+--eval|node\s+-p"; then
      warn "LaunchAgent/Daemon runs node with inline eval: $plist"
      persist_hit=1
    fi

    # Suspicious: recently added plist (within risk window)
    # Skip plists from known-legitimate vendor prefixes — these are installed by
    # corporate software (Microsoft, Zscaler, Apple) and coincide with the window
    # only because IT pushed updates at the same time.
    plist_base=$(basename "$plist" .plist)
    case "$plist_base" in
      com.microsoft.*|com.apple.*|com.zscaler.*|com.google.*|com.adobe.*|\
      com.vmware.*|com.crowdstrike.*|com.jamf.*|com.kandji.*|\
      com.cisco.*|com.sentinelone.*|com.carbonblack.*|com.malwarebytes.*)
        # Trusted vendor — skip date window check
        ;;
      *)
        plist_date=$(stat -f "%Sm" -t "%Y-%m-%d" "$plist" 2>/dev/null || echo "?")
        if [[ "$plist_date" > "2026-05-09" && "$plist_date" < "2026-05-15" ]]; then
          hit "LaunchAgent/Daemon created DURING attack risk window ($plist_date): $plist"
          persist_hit=1
        fi
        ;;
    esac
  done < <(find "$ldir" -name "*.plist" -maxdepth 2 2>/dev/null)
done
[[ $persist_hit -eq 0 ]] && ok "LaunchAgents/Daemons: no suspicious persistence found"

phase "Checking cron jobs for C2 beaconing"
cron_hit=0
all_cron=$(crontab -l 2>/dev/null || true)
if [[ -n "$all_cron" ]]; then
  for kw in "${C2_KEYWORDS[@]}" "curl" "wget" "node -e"; do
    match=$(echo "$all_cron" | grep -i "$kw" || true)
    if [[ -n "$match" ]]; then
      warn "Cron job contains suspicious keyword: $kw"
      echo "$match" | while IFS= read -r l; do detail "$l"; done
      cron_hit=1
    fi
  done
fi

# System-wide cron
for cron_dir in /etc/cron.d /etc/periodic/daily /etc/periodic/weekly; do
  [[ -d "$cron_dir" ]] || continue
  while IFS= read -r cf; do
    for kw in "${C2_KEYWORDS[@]}"; do
      grep -qi "$kw" "$cf" 2>/dev/null && \
        { hit "System cron contains C2 keyword ($kw): $cf"; cron_hit=1; }
    done
  done < <(find "$cron_dir" -type f -maxdepth 1 2>/dev/null)
done
[[ $cron_hit -eq 0 ]] && ok "Cron: no suspicious scheduled tasks found"

S6_HITS=$SEC_HITS; S6_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 7  —  Credential & File Exfiltration Indicators"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}node-ipc and plain-crypto-js exfiltrate SSH keys, AWS creds, npm tokens.${NC}"
_log "  ${DIM}Checks for suspicious reads and staging areas used before upload.${NC}"
_log ""
phase "Checking for suspicious staging files (temp exfil staging)"

STAGING_PATHS=(
  "/tmp/.npm_*"
  "/tmp/tanstack_*"
  "/tmp/ipc_*"
  "/tmp/node_*"
  "/tmp/.plain_*"
  "/tmp/.crypto_*"
  "$HOME/.npm/_tmp_*"
  "$HOME/.config/.node_*"
)

staging_hit=0
for pattern in "${STAGING_PATHS[@]}"; do
  while IFS= read -r f; do
    [[ -e "$f" ]] || continue
    file_date=$(stat -f "%Sm" -t "%Y-%m-%d" "$f" 2>/dev/null || echo "?")
    warn "Suspicious staging file found: $f  (modified: $file_date)"
    staging_hit=1
  done < <(ls $pattern 2>/dev/null || true)
done
[[ $staging_hit -eq 0 ]] && ok "No suspicious exfil staging files in temp directories"

phase "Checking if credential files were recently accessed (within risk window)"

CRED_FILES=(
  "$HOME/.ssh/id_rsa"
  "$HOME/.ssh/id_ed25519"
  "$HOME/.ssh/id_ecdsa"
  "$HOME/.aws/credentials"
  "$HOME/.npmrc"
  "$HOME/.netrc"
  "$HOME/.pypirc"
  "$HOME/.docker/config.json"
  "$HOME/.config/gh/hosts.yml"
)

cred_hit=0
for cf in "${CRED_FILES[@]}"; do
  [[ -f "$cf" ]] || continue
  # Check last access time
  atime=$(stat -f "%Sa" -t "%Y-%m-%d" "$cf" 2>/dev/null || echo "?")
  mtime=$(stat -f "%Sm" -t "%Y-%m-%d" "$cf" 2>/dev/null || echo "?")
  if [[ "$atime" > "2026-05-10" && "$atime" < "2026-05-14" ]]; then
    hit "Credential file ACCESSED during attack risk window: $cf"
    detail "Last accessed: $atime  |  Last modified: $mtime"
    cred_hit=1
  elif [[ "$mtime" > "2026-05-10" && "$mtime" < "2026-05-14" ]]; then
    warn "Credential file MODIFIED during attack risk window: $cf"
    detail "Last modified: $mtime"
    cred_hit=1
  fi
done
[[ $cred_hit -eq 0 ]] && ok "Credential files: none accessed or modified during risk window"

S7_HITS=$SEC_HITS; S7_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
SEC_HITS=0; SEC_WARNS=0
sep2; banner "PHASE 8  —  Firewall & Block Status  (passive — no outbound connections)"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""
_log "  ${DIM}Passive check only. No TCP probes, no DNS queries, no outbound traffic.${NC}"
_log "  ${DIM}Verifies whether C2 IPs and domains are already blocked on this machine.${NC}"
_log ""

phase "macOS pf firewall rules — are C2 IPs blocked?"

pf_rules=$(pfctl -sr 2>/dev/null || true)
pf_blocked=0
if [[ -n "$pf_rules" ]]; then
  for ip in "${ALL_C2_IPS[@]}"; do
    if echo "$pf_rules" | grep -qF "$ip"; then
      ok "C2 IP blocked in pf rules: $ip"
      pf_blocked=$((pf_blocked+1))
    fi
  done
  [[ $pf_blocked -eq 0 ]] && warn "C2 IPs not found in pf firewall rules — traffic to these IPs is not blocked at the OS level"
else
  info "pf firewall not active or requires root (run with sudo to check)"
fi

phase "/etc/hosts — are C2 domains sinkholed?"

hosts_blocked=0
for domain in "${ALL_C2_DOMAINS[@]}"; do
  if grep -qE "^0\.0\.0\.0[[:space:]]+${domain}([[:space:]]|$)" /etc/hosts 2>/dev/null || \
     grep -qE "^127\.0\.0\.1[[:space:]]+${domain}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
    ok "C2 domain sinkholed in /etc/hosts: $domain"
    hosts_blocked=$((hosts_blocked+1))
  fi
done
[[ $hosts_blocked -eq 0 ]] && warn "No C2 domains are sinkholed in /etc/hosts — add 0.0.0.0 entries to block them (see IOC card below)"

phase "Little Snitch / corporate proxy — domain block rules"

ls_db="/Library/Application Support/Obdev/Little Snitch/Rules.xpl"
if [[ -f "$ls_db" ]]; then
  ls_blocked=0
  for domain in "${ALL_C2_DOMAINS[@]}"; do
    if grep -qiF "$domain" "$ls_db" 2>/dev/null; then
      ok "C2 domain found in Little Snitch rules: $domain"
      ls_blocked=$((ls_blocked+1))
    fi
  done
  [[ $ls_blocked -eq 0 ]] && info "Little Snitch present but no rules matched C2 domains"
else
  info "Little Snitch not installed — if behind corporate proxy, blocking may still be in place at the network layer"
fi

phase "pf anchor files — /etc/pf.anchors and /etc/pf.conf"

anchor_blocked=0
for ip in "${ALL_C2_IPS[@]}"; do
  if grep -rqF "$ip" /etc/pf.anchors/ /etc/pf.conf 2>/dev/null; then
    ok "C2 IP found in pf anchor/conf: $ip"
    anchor_blocked=$((anchor_blocked+1))
  fi
done
[[ $anchor_blocked -eq 0 ]] && info "C2 IPs not found in pf anchor files (no host-level IP block in place)"

_log ""
_log "  ${BOLD}${BC}── Recommended Blocking Commands ──────────────────────────────${NC}"
_log "  ${DIM}Run these to block all C2 IPs at the OS firewall (requires sudo):${NC}"
_log ""
for ip in "${ALL_C2_IPS[@]}"; do
  _log "  ${DIM}  sudo pfctl -e && echo 'block drop out quick to ${ip}' | sudo pfctl -f -${NC}"
done
_log ""
_log "  ${DIM}Or add these sinkhole entries to /etc/hosts (no sudo required for blocking, edit needs sudo):${NC}"
_log ""
for domain in "${ALL_C2_DOMAINS[@]}"; do
  _log "  ${DIM}  0.0.0.0   ${domain}${NC}"
done
_log ""

S8_HITS=$SEC_HITS; S8_WARNS=$SEC_WARNS

# ══════════════════════════════════════════════════════════════════════════════
sep2
banner "FINAL SUMMARY  —  C2 Detection Report  [$(elapsed) total]"
sep2
# ══════════════════════════════════════════════════════════════════════════════
_log ""

GRAND_HITS=$((S1_HITS + S2_HITS + S3_HITS + S4_HITS + S5_HITS + S6_HITS + S7_HITS + S8_HITS))
GRAND_WARNS=$((S1_WARNS + S2_WARNS + S3_WARNS + S4_WARNS + S5_WARNS + S6_WARNS + S7_WARNS + S8_WARNS))

_log "  ${BOLD}Scan completed: $(date)${NC}"
_log "  ${BOLD}Host:           $(hostname)${NC}"
_log "  ${BOLD}Elapsed:        $((SECONDS - SCAN_START))s${NC}"
_log ""
_log "  ${BOLD}${W}┌──────────────────────────────────────────────────────┐${NC}"
_log "  ${BOLD}${W}│  PHASE                           C2 HITS   SUSPECTS  │${NC}"
_log "  ${BOLD}${W}├──────────────────────────────────────────────────────┤${NC}"

print_row() {
  local label="$1" hits="$2" warns="$3"
  if [[ $hits -gt 0 ]]; then
    _log "  ${BOLD}${R}│  $label  ${hits}         ${warns}        │${NC}"
  elif [[ $warns -gt 0 ]]; then
    _log "  ${BOLD}${Y}│  $label  ${hits}         ${warns}        │${NC}"
  else
    _log "  ${BOLD}${G}│  $label  ${hits}         ${warns}        │${NC}"
  fi
}

print_row "Phase 1  DNS cache                  " $S1_HITS $S1_WARNS
print_row "Phase 2  Live sockets               " $S2_HITS $S2_WARNS
print_row "Phase 3  Node process forensics      " $S3_HITS $S3_WARNS
print_row "Phase 4  DNS & hosts integrity       " $S4_HITS $S4_WARNS
print_row "Phase 5  System log analysis         " $S5_HITS $S5_WARNS
print_row "Phase 6  Persistence mechanisms      " $S6_HITS $S6_WARNS
print_row "Phase 7  Credential access           " $S7_HITS $S7_WARNS
print_row "Phase 8  Firewall & block status     " $S8_HITS $S8_WARNS

_log "  ${BOLD}${W}├──────────────────────────────────────────────────────┤${NC}"
_log "  ${BOLD}${W}│  TOTAL                           $GRAND_HITS         $GRAND_WARNS        │${NC}"
_log "  ${BOLD}${W}└──────────────────────────────────────────────────────┘${NC}"
_log ""

if [[ $GRAND_HITS -gt 0 ]]; then
  _log "  ${BR}${BOLD}  ██████████████████████████████████████████████████${NC}"
  _log "  ${BR}${BOLD}  ◉  CONFIRMED C2 COMMUNICATION DETECTED             ${NC}"
  _log "  ${BR}${BOLD}  ██████████████████████████████████████████████████${NC}"
  _log ""
  _log "  ${BR}  IMMEDIATE ACTIONS REQUIRED:${NC}"
  _log "  ${R}  1. DISCONNECT this machine from the network NOW${NC}"
  _log "  ${R}  2. Rotate ALL credentials that exist on this machine:${NC}"
  _log "  ${R}     → SSH keys:       ssh-keygen -t ed25519 (new keys, revoke old)${NC}"
  _log "  ${R}     → AWS:            aws iam delete-access-key + new key${NC}"
  _log "  ${R}     → npm token:      npm token revoke <token>${NC}"
  _log "  ${R}     → GitHub PAT:     Settings → Developer settings → revoke${NC}"
  _log "  ${R}     → Docker Hub:     Account Settings → Security → revoke${NC}"
  _log "  ${R}  3. Check your git repos for unexpected commits${NC}"
  _log "  ${R}  4. Check cloud provider for unauthorized API activity${NC}"
  _log "  ${R}  5. File incident report with your security team${NC}"
  _log ""
  _log "  ${R}  FORENSIC EVIDENCE saved to: $LOGFILE${NC}"
  _log "  ${R}  Share this log with your security team / IR team${NC}"
elif [[ $GRAND_WARNS -gt 0 ]]; then
  _log "  ${BY}${BOLD}  ⚠  NO CONFIRMED C2 HITS — $GRAND_WARNS item(s) warrant manual review${NC}"
  _log ""
  _log "  ${Y}  RECOMMENDED ACTIONS:${NC}"
  _log "  ${Y}  • Review the SUSPECT items above — they may be false positives${NC}"
  _log "  ${Y}  • If on corporate network, check if public DNS is expected${NC}"
  _log "  ${Y}  • Re-run after removing any malicious packages found by the vulnerability scanner${NC}"
  _log "  ${Y}  • Consider rotating npm tokens as a precaution${NC}"
else
  _log "  ${BG}${BOLD}  ✔  CLEAN — no C2 or command-and-control communication detected${NC}"
  _log ""
  _log "  ${G}  This machine shows no signs of active or historical C2 contact${NC}"
  _log "  ${G}  from any of the three supply-chain attacks.${NC}"
fi

_log ""
_log "  ${DIM}Full forensic log: $LOGFILE${NC}"
_log ""

# ── IOC Reference Card ────────────────────────────────────────────────────────
sep2
_log "${BOLD}${BC}  IOC REFERENCE — C2 Infrastructure for All Three Attacks${NC}"
sep2
_log ""
_log "  ${BOLD}node-ipc backdoor${NC}"
_log "  ${DIM}  Domains:  sh.azurestaticprovider.net   bt.node.js (DNS exfil)${NC}"
_log "  ${DIM}  IP:       37.16.75.69${NC}"
_log "  ${DIM}  Payload:  peacenotwar  (co-installed as dependency)${NC}"
_log ""
_log "  ${BOLD}TanStack CVE-2026-45321${NC}"
_log "  ${DIM}  Domains:  cdn-tanstack-router.vercel-dns.com${NC}"
_log "  ${DIM}            tanstack-telemetry.workers.dev${NC}"
_log "  ${DIM}            router-analytics.tanstack-cdn.com${NC}"
_log "  ${DIM}  IOC files: router_init.js  tanstack_runner.js${NC}"
_log ""
_log "  ${BOLD}Axios + plain-crypto-js${NC}"
_log "  ${DIM}  Domains:  plain-crypto.vercel.app   analytics.plain-crypto.com${NC}"
_log "  ${DIM}            api.cryptojs-cdn.net   data-collect.axios-cdn.workers.dev${NC}"
_log "  ${DIM}  Payload:  plain-crypto-js@4.2.1${NC}"
_log ""
_log "  ${DIM}To block all C2 at the firewall level, add these IPs to your deny list:${NC}"
for ip in "${ALL_C2_IPS[@]}"; do _log "  ${DIM}    $ip${NC}"; done
_log ""
