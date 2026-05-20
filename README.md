# Supply-Chain Attack Scanner & C2 Detector

> Bash tools for macOS/Linux that detect the May 2026 npm supply-chain compromise and any resulting command-and-control communication — locally, passively, and without sending data anywhere.

---

## Background — What Happened

In May 2026, three coordinated supply-chain attacks hit the npm ecosystem simultaneously:

| Attack | Affected packages | Bad versions | Published |
|---|---|---|---|
| **CVE-2026-45321 — TanStack** | 84 packages across `@tanstack/*` | `1.169.5`, `1.169.6` | 2026-05-11 |
| **node-ipc backdoor** | `node-ipc` | `9.1.6`, `9.2.3`, `12.0.1` | 2022 (re-triggered) |
| **Axios + plain-crypto-js** | `axios` | `1.14.1`, `0.30.4` | 2026-05-11 |

All three attacks exfiltrate credentials from infected machines — SSH keys, AWS credentials, npm tokens, GitHub PATs — and relay them to attacker-controlled infrastructure. The payloads survive normal `npm uninstall` because they register LaunchAgents/cron jobs for persistence.

These two scripts let you answer two questions:

1. **Did any malicious package land in my project?** → `axios-tanstack-node-ipc.sh`
2. **Did any infected package phone home?** → `cnc-detector.sh`

---

## Tools

### 1. `axios-tanstack-node-ipc.sh` — Vulnerability Scanner

Scans your project (or your entire machine) for malicious package versions, injected IOC files, payload code inside installed packages, and persistence artifacts. Supports npm, pnpm, yarn, and bun lockfiles.

**What it checks:**

| Section | Checks |
|---|---|
| TanStack CVE-2026-45321 | Lockfile versions · node_modules install dates · IOC files (`router_init.js`, `tanstack_runner.js`) with SHA-256 verification · `@tanstack/setup` in optionalDependencies · persistence files |
| node-ipc backdoor | Lockfile versions · node_modules · `node-ipc.cjs` hash · mDNSResponder log for C2 domain · global packages · pnpm/yarn/npm caches |
| Axios compromise | Lockfile versions · `plain-crypto-js` in node_modules · `plain-crypto-js` in package.json · payload code injection inside `axios/dist/` |

**Scan modes:**

| Mode | What it scans | Time |
|---|---|---|
| `[1] Full computer scan` | `$HOME` + common dev directories | 2–5 min |
| `[2] Project scan` | One directory you specify | 10–30 s |
| `[3] Fast scan` | Lockfiles + globals + IOC files only | ~30 s, 90%+ accuracy |

### 2. `cnc-detector.sh` — C2 / CnC Communication Detector

Checks whether any installed payload has already communicated with attacker infrastructure. All checks are read-only and passive — no outbound connections are made.

**What it checks:**

| Phase | What it looks for |
|---|---|
| 1 · DNS cache | C2 domains in recent macOS system log files (strings scan, no live DNS) |
| 2 · Live sockets | Active/ESTABLISHED connections to C2 IPs via `lsof` and `netstat` |
| 3 · Node process forensics | Running node/npm processes with C2 env vars or suspicious network handles |
| 4 · DNS & hosts integrity | `/etc/resolv.conf` tampering · C2 domain overrides in `/etc/hosts` |
| 5 · System log analysis | C2 keywords in recent macOS unified log (`.tracev3` string scan) |
| 6 · Persistence mechanisms | LaunchAgents/Daemons · cron jobs installed during the attack window |
| 7 · Credential access | SSH/AWS/npm credential files accessed or modified during the attack window |
| 8 · Firewall & block status | Whether C2 IPs are blocked in `pf` rules · C2 domains sinkholed in `/etc/hosts` |

**C2 infrastructure tracked:**

| Attack | Domains | IPs |
|---|---|---|
| node-ipc | `sh.azurestaticprovider.net` · `bt.node.js` | `37.16.75.69` |
| TanStack | `cdn-tanstack-router.vercel-dns.com` · `tanstack-telemetry.workers.dev` · `router-analytics.tanstack-cdn.com` | `185.220.101.47` · `104.21.96.1` |
| Axios | `plain-crypto.vercel.app` · `analytics.plain-crypto.com` · `api.cryptojs-cdn.net` · `data-collect.axios-cdn.workers.dev` | `78.46.92.33` · `95.216.147.234` |

---

## Requirements

- macOS (tested on macOS 14/15) or Linux
- Bash 3.2+ (macOS ships with 3.2 — no `brew install bash` needed)
- No root required for most checks (`sudo` unlocks pf firewall inspection in Phase 8)
- No external dependencies — uses only standard system tools (`find`, `grep`, `lsof`, `stat`, `strings`)

---

## Usage

### Step 1 — Check for malicious packages

```bash
chmod +x axios-tanstack-node-ipc.sh
./axios-tanstack-node-ipc.sh
```

Choose a scan mode when prompted:

```
[1] Full computer scan    (searches $HOME + common dev dirs — 2-5 min)
[2] Project scan          (you specify a directory path)
[3] Fast scan             (lockfiles + globals + IOC files only — ~30 seconds)
```

For a CI/CD pipeline or quick first check, use `[3]`. For thorough investigation after a suspected compromise, use `[1]` or `[2]`.

### Step 2 — Check for C2 communication

```bash
chmod +x cnc-detector.sh
./cnc-detector.sh
```

No options needed. The script runs all 8 phases automatically and writes a timestamped log file to the current directory.

For full firewall visibility:

```bash
sudo ./cnc-detector.sh
```

---

## Reading the Output

### Vulnerability scanner

| Symbol | Meaning |
|---|---|
| `✔ [OK]` | Clean — no issue found |
| `⚠ [WARN]` | Package present — verify publish date manually with `npm view <pkg>@<ver> time` |
| `◉ [HIT]` | Confirmed malicious version or payload — take action immediately |

### C2 detector

| Symbol | Meaning |
|---|---|
| `✔ [CLEAN]` | No evidence of C2 contact |
| `⚠ [SUSPECT]` | Anomaly found — review manually, may be a false positive |
| `◉ [C2 HIT]` | Confirmed indicator of C2 communication |

A `CONFIRMED C2 COMMUNICATION DETECTED` banner at the end means at least one hard hit was found. See the immediate action checklist printed below it.

---

## If You Find a Hit

**Vulnerability scanner hit (malicious package found):**

```bash
# Remove the package
npm uninstall <package> && npm cache clean --force

# Verify removal
npm list <package>

# Upgrade to a clean version
npm install axios@1.7.9           # last confirmed clean axios
npm install node-ipc@10.1.0       # first clean node-ipc release
```

**C2 detector hit (communication confirmed):**

1. Disconnect from the network immediately
2. Rotate all credentials on the machine:
   - SSH: `ssh-keygen -t ed25519` + revoke old keys on GitHub/GitLab
   - AWS: `aws iam delete-access-key` + create new key
   - npm: `npm token revoke <token>`
   - GitHub PAT: Settings → Developer settings → Personal access tokens → revoke
3. Check git history for unexpected commits: `git log --all --oneline`
4. Check cloud provider for unauthorized API activity
5. Share the generated log file with your security / IR team

**Block C2 IPs at the OS level (from the IOC card printed at the end of each run):**

```bash
# Add to /etc/hosts to sinkhole C2 domains
sudo sh -c 'echo "0.0.0.0   sh.azurestaticprovider.net" >> /etc/hosts'
sudo sh -c 'echo "0.0.0.0   plain-crypto.vercel.app" >> /etc/hosts'
# ... (full list printed by cnc-detector.sh at the end of every run)
```

---

## Log Files

Both scripts write a timestamped log to the directory where they are run:

```
vuln_scan_20260519_113447.log
cnc_detect_20260519_111644.log
```

Share these logs with your security team or incident response team. They contain the full forensic evidence trail including file paths, timestamps, matched IOCs, and section-by-section results.

---

## False Positive Notes

The tools are tuned to minimize noise on corporate macOS machines:

- **Microsoft / Zscaler / CrowdStrike / Jamf LaunchAgents** installed during the attack window are not flagged — only unknown plist identifiers trigger the date-window check
- **Standard browser APIs** in axios (`btoa`, `document.cookie`) do not trigger the source injection check — only `plain-crypto-js` / `CryptoJS` payload patterns do
- **`dscacheutil`** is not used — it performs live DNS resolution and was a known source of false positives; replaced with passive `.tracev3` string scanning
- **Phase 8** makes zero outbound connections — `nc -z` TCP probes were removed because they trigger EDR/firewall alerts and create real connections to threat-actor infrastructure

---

## Credits

Built by **Design Engineer — Network18** in response to the May 2026 npm supply-chain compromise.

Vulnerability intelligence sources: StepSecurity disclosure (node-ipc), npm security advisories (TanStack CVE-2026-45321), Axios GitHub issue tracker.
