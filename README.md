# PolinRider Shield 🛡️

A Windows and macOS security tool for the **PolinRider/Lazarus Group npm supply chain attack**.

- **Windows:** Full scanner and lockdown tool - detects threats and automatically applies protections
- **macOS:** Forensic scanner only - detects threats, manual lockdown steps required

---

## What is PolinRider?

PolinRider is a supply chain attack campaign attributed to the **DPRK Lazarus Group / BlueNoroff**. As of August 2026 it has compromised over 2,000 GitHub repositories across multiple unique owners, with numbers growing rapidly since its first detection in early 2026.

**How it works:**
1. A malicious npm package or compromised fork is installed or cloned
2. A hidden `.vscode/tasks.json` file auto-executes when the project is opened in VS Code or Cursor
3. A fake font file (`fa-solid-400.woff2`) containing JavaScript payload runs silently
4. The payload connects to blockchain networks (TRON, Aptos, BSC) to fetch C2 instructions
5. Credentials and tokens are stolen from the developer machine
6. The stolen GitHub token is used to push malware into the developer's other repos
7. The cycle repeats on every developer who clones an infected repo

**Capabilities of the payload:**
- Credential and browser data theft
- Cryptocurrency wallet theft
- Keylogging
- Remote code execution via a RAT (Remote Access Trojan)
- Persistent backdoor installation
- Git history falsification to hide the attack

---

## Tools included

| File | Platform | Scan | Lockdown |
|---|---|---|---|
| `windows/file-scanner.bat` | Windows | ✅ | ✅ Automatic |
| `mac/check-polinrider-mac.sh` | macOS | ✅ | ❌ Manual steps required |
| `.github/workflows/security-scan.yml` | GitHub Actions | ✅ | ❌ |

> **macOS users:** The Mac script is a read-only forensic scanner and does not change any settings. After running the scan, apply the lockdown steps manually - see the [Mac Manual Lockdown](#mac-manual-lockdown) section below.

---

## Windows (`file-scanner.bat`)

### Requirements
- Windows 10 or 11
- PowerShell 3.0 or later
- Run as Administrator for full protection

### How to run
1. Download `windows/file-scanner.bat`
2. Right-click the file
3. Select **Run as administrator**
4. Press any key to start

### What it scans
| Step | Check |
|---|---|
| A1 | Malicious filenames across all drives (parallel) |
| A2 | Infected `.gitignore` entries (parallel) |
| A3 | `tasks.json` with `folderOpen` triggers (parallel) |
| A4 | Hidden payloads in build config files (parallel) |
| A5 | Beavertail artifacts, payload execution, suspicious processes, exfil archives, browser credentials, startup persistence (parallel) |
| A6 | Git history scan across all repos on D drive (last 3 months, parallel) |

### What it locks down automatically
| Step | Action |
|---|---|
| B1 | Sets `npm ignore-scripts=true` to block malicious install hooks |
| B2 | Disables VS Code and Cursor auto tasks and enforces Workspace Trust |
| B3 | Blocks known PolinRider C2 IPs in Windows Firewall |

### Result colors
- 🔴 **INFECTED** - Threat detected, take action immediately
- 🟡 **REVIEW** - Review manually, may not be malicious
- 🟢 **SAFE** - No threats found

### Configurable variables
At the top of the script:
```bat
REM PolinRider C2 IPs - update if new IPs are discovered
set C2_IPS=166.88.134.62,198.105.127.210,23.27.202.27,166.88.54.158

REM Git history scan depth - "3 months ago", "6 months ago", "1 year ago"
set GIT_HISTORY=3 months ago
```

---

## macOS (`check-polinrider-mac.sh`)

### Requirements
- macOS
- bash
- git

### How to run
```bash
# Quick scan
bash mac/check-polinrider-mac.sh

# Deep scan including full git history
DEEP_GIT=1 bash mac/check-polinrider-mac.sh

# Scan specific folders
bash mac/check-polinrider-mac.sh ~/work ~/repos
```

> This script is **read-only** and changes nothing on your machine.

---

## Mac Manual Lockdown

After running the Mac scanner, apply these protections manually:

**1. npm ignore-scripts:**
```bash
npm config set ignore-scripts true
```

**2. VS Code and Cursor auto tasks:**

Open `~/Library/Application Support/Code/User/settings.json` and `~/Library/Application Support/Cursor/User/settings.json` and add:
```json
{
    "task.allowAutomaticTasks": "off",
    "security.workspace.trust.enabled": true,
    "security.workspace.trust.startupPrompt": "always",
    "security.workspace.trust.emptyWindow": false,
    "security.workspace.trust.untrustedFiles": "open"
}
```

**3. Block C2 IPs:**
```bash
sudo /sbin/pfctl -e
echo "
block drop out quick to 166.88.134.62
block drop out quick to 198.105.127.210
block drop out quick to 23.27.202.27
block drop out quick to 166.88.54.158
" | sudo /sbin/pfctl -f -
```

---

## GitHub Actions Workflow (`security-scan.yml`)

Automatically scans every PR and push to `master`, `main`, and `develop`.

### How to add to your repo
```bash
mkdir -p .github/workflows
cp .github/workflows/security-scan.yml your-repo/.github/workflows/
git add .github/workflows/security-scan.yml
git commit -m "security: add PolinRider detection workflow"
git push
```

### What it checks on every PR
- Lines longer than 500 characters in config files
- Known PolinRider malware signatures
- Fake font files with JavaScript payloads
- Malicious `folderOpen` triggers in `tasks.json`
- Known malicious filenames
- Malware entries in `.gitignore`

---

## Known Indicators of Compromise

### Malicious files
- `public/fonts/fa-solid-400.woff2` (fake font containing JavaScript)
- `temp_auto_push.bat`
- `temp_interactive_push.bat`
- `branch_structure.json`
- `.vscode/tasks.json` with `folderOpen` + font file execution

### Malware signatures in config files
- `A8-261` (campaign ID)
- `rmcej%otb%`
- `global['r']=require`
- `:443/0x/ls` or `:443/0x/cl` (C2 paths)
- `0xa322E5f3` (attacker wallet)
- `trongrid.io` (blockchain C2)

### Payload execution artifacts (Windows)
- `%USERPROFILE%\.node_modules`
- `%LOCALAPPDATA%\Programs\Python\Python3127`
- `%TEMP%\.npm`
- `tmp7A863DD1.tmp`

### C2 IP addresses
- `166.88.134.62`
- `198.105.127.210`
- `23.27.202.27`
- `166.88.54.158`

---

## If you find an infection

1. **Do not open** any flagged project in VS Code or Cursor
2. **Do not run** `npm install`, `npm test`, or `npm build` in any flagged repo
3. **Rotate credentials immediately** from a different device:
   - GitHub tokens and SSH keys
   - npm publish tokens
   - AWS and cloud credentials
   - Any API keys in `.env` files
4. **Check GitHub** for any commits you did not make
5. **Report** to your security team

---

## References

- [OpenSourceMalware PolinRider Dossier](https://github.com/OpenSourceMalware/PolinRider)
- [Wiz Threat Intelligence](https://threats.wiz.io/all-incidents/polinrider-campaign-dprk-linked-supply-chain-attack-infects-github-repositories)
- [Mallory.ai PolinRider Profile](https://mallory.ai/malware/019cd938-8511-7560-a9ca-2921a859df50)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided as-is for educational and defensive purposes. Run at your own risk. Always review scripts before executing them on your machine.
