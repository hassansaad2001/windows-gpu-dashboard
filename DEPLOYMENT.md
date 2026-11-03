# AI Server Dashboard: Deployment Guide

A monitoring and management dashboard for a shared, multi-user Windows Server that runs AI/GPU work
(tested on Windows Server 2022; NVIDIA GPUs optional). It runs as a Windows service
and serves a web UI to browsers on the LAN.

| What | Where |
|---|---|
| Source | the folder you cloned this repository into |
| Install folder (after install) | `C:\AIDashboard` (Administrators/SYSTEM only) |
| Database | `C:\AIDashboard\data\server_stats.db` (SQLite, WAL) |
| Logs | `C:\AIDashboard\logs\dashboard.log`, `service.log` |
| Service | `AIDashboard`: NSSM, LocalSystem, delayed auto-start, restarts on failure |
| URL | `https://<server-name>:8443` or `https://<server-ip>:8443` |

---

## 1. What it does

**Collectors (background threads)**

| Job | Interval | Source |
|---|---|---|
| CPU / RAM / GPU sample | 60 s (stored per minute, aggregated per hour) | `psutil`, `nvidia-smi` |
| Per-process GPU memory/utilization | with each rogue scan | Windows *GPU Process Memory* / *GPU Engine* performance counters |
| Home-folder sizes | 60 min | the profiles folder (usually `C:\Users\*`), mapped to accounts via the registry ProfileList |
| NTFS per-owner usage | 60 min | `fsutil quota query` (only on volumes with quotas enabled) |
| Restart history | 60 min | System log: Kernel-General 12/13, User32 1074/1076, Kernel-Power 41, EventLog 6008 |
| Rogue process scan | 5 min | `psutil` + WTS sessions + GPU counters |
| Quota evaluation | 60 min | policies in the DB → `fsutil quota modify/enforce` |

> **Why Windows counters for per-process GPU usage?** GeForce cards run in WDDM mode on Windows,
> so `nvidia-smi`/NVML can't attribute VRAM to processes (they show `[Insufficient Permissions]`/`N/A`).
> The WDDM performance counters can. Counter instances are keyed by adapter LUID, and the dashboard
> maps each LUID to its `nvidia-smi` index by matching per-adapter memory use.
>
> **GPU jobs inside WSL.** CUDA work in WSL2 is charged to the VM's worker process (`vmwp.exe`),
> which runs under a per-VM account. The dashboard shows it as `vmwp.exe (WSL VM)` and charges it to the
> user who owns that VM's `wslhost.exe`/`wslrelay.exe` processes (matched by `--vm-id`). The dashboard
> won't terminate a VM worker, because killing it is a hard power-off that can corrupt the user's Linux
> disk. Ask the user to stop the job or run `wsl --shutdown`, or log off their session.

**Restart classification**

- *Planned restart / shutdown*: event 1074, with the initiating process, user, reason and comment.
- *Unexpected, power failure or hard hang*: Kernel-Power 41 with no bugcheck and no power-button press.
  The "down since" time is read from event 6008's binary data, so the outage length is shown.
- *Unexpected, system crash (bugcheck 0x…)*: Kernel-Power 41 with a bugcheck code.
- *Forced power-off (power button)*: Kernel-Power 41 with a power-button timestamp.
- If an admin later fills in the "why did it shut down" dialog (event 1076), that reason and user are shown.

Rows are stored in the database by boot time, so history outlives the System log. The installer
also enlarges the System log from 20 MB to 256 MB. At 20 MB it only held about one month.

**Rogue-process rules** (thresholds are in `config.json` → `rogue`)

A process is a candidate if it runs under a real user account and is either on the watch list
(python, conda, jupyter, ollama, llama-server, torchrun, …), holds GPU memory, or uses more CPU than
the threshold. DataLoader-style worker children are folded into their parent. Flags:

| Flag | Severity |
|---|---|
| **orphaned**: owner has no logon session at all | high |
| **detached**: runs in session 0 or outside the owner's session (scheduled task, `runas`, SSH) | medium |
| **idle**: owner's session has been disconnected longer than `idle_disconnected_hours` (24 h) | medium |
| **multi-GPU**: holds ≥ `multi_gpu_threshold` GPUs (3) | medium |
| **GPU-heavy** (≥ 6 GB VRAM), **CPU-heavy** (≥ 400 % ≈ 4 cores), **long-running** (≥ 72 h) | low |

Any medium/high flag on a process holding ≥ 1 GB VRAM is raised to **high**. Add accounts or
process names to `whitelist_users` / `whitelist_names` to stop them being flagged.
Jobs started over SSH run in session 0 and count as *detached*. That is intended: they keep running
after the SSH connection closes.

**Access control**

- Users sign in with their **Windows account on this server** (validated with `LogonUser`).
- Every enabled local account can **view**. Members of the local **Administrators** group can also
  terminate processes, log off sessions, run jobs and manage quotas.
- Sessions are in memory (8 h). After 5 failed sign-ins from one IP, that IP must wait 5 minutes.
  Failed attempts also count toward Windows' account-lockout policy.
- Admin API calls need a custom header (CSRF guard). Cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` over HTTPS.
  The page sends a strict CSP and frame-denial headers.
- Every sign-in and admin action goes to the **Audit log** panel (`audit_log` table).
- Process termination checks the PID's creation time (so a reused PID is never killed) and refuses
  system accounts, protected processes (csrss, lsass, winlogon, explorer, …) and the dashboard itself.

---

## 2. Install

**Requirements:** Python 3.10+ installed *for all users* (for example `C:\Program Files\Python312`; the
Microsoft Store build does not work for services), internet access for `pip` and the NSSM download
(or put `nssm.exe` on PATH first). For GPU metrics, the NVIDIA driver with `nvidia-smi` on PATH;
without it everything else still works.

From an **elevated** PowerShell (an SSH session as an administrator works):

```powershell
cd <path-to-this-repository>
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

Options:

```powershell
# different port / plain HTTP / tighter firewall scope
scripts\install.ps1 -Port 8080 -NoHttps -RemoteAddress 192.168.1.0/24
```

The installer:

1. Copies `app\`, `scripts\` and `requirements.txt` to `C:\AIDashboard`. On re-run it upgrades in place and keeps `config.json`, the DB and the certificate.
2. Creates `C:\AIDashboard\venv` and installs `fastapi uvicorn psutil pywin32 cryptography`.
3. Generates a self-signed certificate (`certs\server.crt/.key`) for the hostname, localhost and every IPv4 address.
4. Removes inherited permissions on `C:\AIDashboard` and grants only **Administrators** and **SYSTEM**.
5. Downloads NSSM 2.24 to `C:\AIDashboard\bin\nssm.exe` and registers the service.
6. Adds the firewall rule and enlarges the System event log.
7. Starts the service and checks that the port answers.

### What the NSSM registration does (for reference / manual install)

```powershell
$d = "C:\AIDashboard"; $n = "$d\bin\nssm.exe"
& $n install AIDashboard "$d\venv\Scripts\python.exe" "-m app.main"
& $n set AIDashboard AppDirectory $d
& $n set AIDashboard DisplayName "AI Server Dashboard"
& $n set AIDashboard Start SERVICE_DELAYED_AUTO_START
& $n set AIDashboard ObjectName LocalSystem
& $n set AIDashboard AppStdout "$d\logs\service.log"
& $n set AIDashboard AppStderr "$d\logs\service.log"
& $n set AIDashboard AppRotateFiles 1
& $n set AIDashboard AppRotateBytes 10485760
& $n set AIDashboard AppExit Default Restart
& $n set AIDashboard AppRestartDelay 5000
sc.exe failure AIDashboard reset= 86400 actions= restart/10000/restart/30000/restart/60000
```

**Why LocalSystem:** the service has to read every user's processes, end them, run `fsutil quota`,
log off sessions and validate passwords. Only Administrators and SYSTEM can read the install folder.

### Firewall

The installer creates:

```powershell
New-NetFirewallRule -DisplayName "AI Server Dashboard (TCP 8443)" -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 8443 -RemoteAddress LocalSubnet -Profile Domain,Private
```

`LocalSubnet` admits every address on the subnets of the server's adapters. To allow only specific
admin workstations, re-run with `-RemoteAddress 192.168.1.10,192.168.1.11`. Keep TCP 8443 inside the
LAN; don't forward it on your router or expose it to the internet.

### Remote access (optional)

To reach the dashboard from a phone or laptop on any network without opening a port, put the server
and your devices on a private overlay network such as [Tailscale](https://tailscale.com) or WireGuard,
and add a firewall rule that admits only that network. For Tailscale (CGNAT range, Tailscale adapter only):

```powershell
New-NetFirewallRule -DisplayName "AI Server Dashboard (Tailscale, TCP 8443)" -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 8443 -RemoteAddress 100.64.0.0/10 -InterfaceAlias Tailscale -Profile Any
```

Install Tailscale in unattended mode (`tailscale up --unattended`) so it stays connected when nobody is
signed in, then open `https://<tailscale-ip>:8443` from your devices. The installer replaces only its
own LAN rule, so this rule survives upgrades. Revoke a lost device in the Tailscale admin console.

### HTTPS certificate

The self-signed certificate triggers a browser warning on first visit. To remove the warning:

- **Per client:** import `C:\AIDashboard\certs\server.crt` into *Trusted Root Certification Authorities*, or
- **Properly:** get a certificate from your organization's CA for the server's DNS name. Save it as PEM to
  `certs\server.crt` / `certs\server.key` (or point `cert_file` / `key_file` in `config.json` at it),
  then `Restart-Service AIDashboard`.

Leave HTTPS on: users type their Windows passwords into the sign-in form.

---

## 3. Storage quotas (NTFS)

### How enforcement works

NTFS quotas are **per volume, per file owner**. When a user reaches their *limit* on a volume where
quotas are *enforced*:

- creating or growing files fails with **"There is not enough space on the disk"** (ERROR_DISK_FULL),
- **reading, renaming and deleting still work**,
- writing works again as soon as usage drops below the limit. Nothing has to be reset.

NTFS charges *every file the user owns on the volume*, not only their profile folder. The storage
table shows both numbers: the home-folder size from the scan, and the NTFS-owned total. Files created by an
elevated administrator are owned by the Administrators group, so admins are effectively exempt.
The "All users" policy also skips local administrators (direct or through a nested group),
accounts that run a Windows service, and anything listed in `quota.exempt_users`.

### Safety rules

The dashboard never deletes, moves or edits files; NTFS quotas only refuse new writes. A refused
write can still break a job that is writing at that moment, so:

- **WSL and Docker disks are never limited.** A user whose WSL or Docker Desktop virtual disk
  (`.vhdx`) is on a volume and charged to them gets only the warning threshold there, never a
  limit: a Linux disk that cannot grow gets I/O errors and can be corrupted. Their status shows
  **vm-protected** and they are still notified. Disks are found in the usual profile folders and
  in the WSL registry of logged-on users, and remembered for 30 days. Turn this off with
  `quota.protect_vm_disks: false` only if those disks live on a volume without limits.
- **Enforcement is switched on only when the volume's default limit is "No limit"**, so accounts
  without an explicit entry are never limited. Otherwise no limits are set and the volume shows
  a red "default limit" badge; fix it with `setup-quotas.ps1 -Action Enforce`.
- **Limits must be at least 1 GB**, and saving a policy first shows a preview: who is blocked as
  soon as you save, who enters a grace period, who is warned, who is protected and who is not covered.
- **Status is what NTFS really does.** *blocked* means NTFS holds a limit the user is at.
  *not-enforced* means the policy would block but the limit could not be applied; the Note
  column says why.
- Limits are lifted when a policy is removed, or when an account is disabled or deleted. A failed
  lift is retried at every evaluation.

### Policy modes (Dashboard → Storage quotas)

| Mode | Behaviour |
|---|---|
| **Soft (warn only)** | NTFS warning threshold = soft limit. Users above it are flagged, notified and logged. Nothing is blocked. |
| **Hard** | NTFS limit = hard limit, applied immediately (threshold = soft, if set). |
| **Soft + grace, then block** *(recommended)* | Above the soft limit a grace timer starts and the user is notified daily. If they are still over after *grace days*, the NTFS limit is set to the soft limit and writes are blocked. An optional hard limit is enforced at all times as a ceiling. When usage drops back under, the escalated limit is lifted automatically. |

A policy for a specific user overrides the "All non-admin users" policy on the same volume.
Removing a policy lifts the limits it set at the next evaluation, which runs immediately.

**Notifications:** an over-limit user gets a pop-up in each of their sessions (`WTSSendMessage`,
repeated every `notify_repeat_hours`). The dashboard also writes an Application event-log entry,
source `AIDashboard`: ID **3001** for a warning or grace period, **3002** for blocked. You can attach
a Task Scheduler email or alert action to those events.

### First-time volume setup

Saving a *hard* or *grace* policy turns on enforcement for that volume automatically. A *soft*
policy turns on tracking. To turn on tracking ahead of time and let NTFS build its usage table
(this can take a while on large volumes):

```powershell
cd C:\AIDashboard\scripts
.\setup-quotas.ps1 -Volume C: -Action Track      # usage tracking only, nothing blocked
.\setup-quotas.ps1 -Volume C: -Action Status     # flags, defaults, per-user entries
```

Other actions: `-Action Enforce`, `-Action Disable`, `-Action Report` (entries plus violations),
and `-Action SetUser -User alice -WarningGB 180 -LimitGB 200`.

The script keeps the volume's **default** quota for new users at *No limit*. Enforcement then
only affects users who have an explicit entry, which the dashboard creates from your policies.
Check it with `-Action Status` (`DefaultLimit = -1` means No limit).

Equivalent raw commands:

```powershell
fsutil quota track C:                                   # enable tracking
fsutil quota enforce C:                                 # enable enforcement
fsutil quota modify C: 214748364800 268435456000 %COMPUTERNAME%\alice   # warn 200 GB, limit 250 GB
fsutil quota query C:                                   # list entries
fsutil quota disable C:                                 # turn off (all limits stop applying)
```

### Suggested rollout

1. Run `setup-quotas.ps1 -Action Track` on each data volume, and wait for the "NTFS owned" column to fill in.
2. Add an **All non-admin users / Soft** policy at a generous level and see who is flagged.
3. Announce the limits, then switch to **Soft + grace** (for example soft 200 GB, hard 300 GB, 7 days).
4. Add per-user overrides for people with approved large datasets.

---

## 4. Operating it

```powershell
Get-Service AIDashboard
Restart-Service AIDashboard
Get-Content C:\AIDashboard\logs\dashboard.log -Tail 50 -Wait
C:\AIDashboard\bin\nssm.exe edit AIDashboard      # GUI for service settings (run at the console)
```

**Configuration** lives in `C:\AIDashboard\config.json`. Keys you leave out use their defaults
(see `app\config.py`). Restart the service after editing. Useful keys:

- `port`, `https`, `public_read` (true = viewing needs no sign-in, admin actions still do)
- `allowed_users`: if set, only these Windows accounts can sign in, e.g. `["admin1", "admin2"]`. Other accounts
  get the same "invalid username or password" answer, and their passwords are never checked. Keep
  `public_read` false, or anyone on the LAN can still view the dashboard without signing in.
- `intervals.*`: collector intervals
- `storage.profile_root`: profiles folder to scan (empty = detected from the registry)
- `storage.quota_volumes`: volumes whose NTFS usage is read (empty = every fixed NTFS volume)
- `rogue.*`: thresholds and whitelists
- `quota.grace_days`, `quota.notify_users`, `quota.exempt_users`, `quota.protect_vm_disks` (true)
- `retention.raw_days` (7) / `retention.hourly_days` (730)

**Upgrade:** edit the source, then re-run `scripts\install.ps1`. Config, data and the certificate are kept.

**Back up:** copy `C:\AIDashboard\data\server_stats.db` (it is safe to copy while running, since it uses WAL mode),
together with `config.json`.

**Uninstall:**

```powershell
C:\AIDashboard\scripts\uninstall.ps1               # service + firewall rule
C:\AIDashboard\scripts\uninstall.ps1 -RemoveFiles  # also deletes C:\AIDashboard (and the DB)
```

Uninstalling first lifts every quota warning and limit the dashboard set, so nobody stays
blocked (`-KeepQuotaLimits` leaves them). Quota tracking or enforcement on the volume is left
as it is; `setup-quotas.ps1 -Action Disable` turns it off.

---

## 5. API (for scripts)

All JSON. Send the session cookie, and add the `X-Requested-With: aidash` header on admin calls.

| Method | Path | Role |
|---|---|---|
| POST | `/api/login` `{username, password}` · `/api/logout` | – |
| GET | `/api/overview` · `/api/trends?range=1h\|24h\|7d\|30d\|12m` | viewer |
| GET | `/api/storage` · `/api/storage/history?days=30` · `/api/restarts` | viewer |
| GET | `/api/processes[?refresh=1]` · `/api/rogue/history` · `/api/quota` | viewer |
| POST | `/api/processes/{pid}/terminate` `{create_time, tree}` | admin |
| POST | `/api/sessions/{id}/logoff` | admin |
| POST/DELETE | `/api/quota/policies` · `/api/quota/policies/{id}` | admin |
| POST | `/api/quota/preview` (same body as a policy; changes nothing) | admin |
| POST | `/api/jobs/{rogue\|events\|storage\|quota\|metrics}/run` · GET `/api/audit` | admin |

## 6. Files

```
app/
  main.py        FastAPI app, routes, entry point (python -m app.main)
  config.py      defaults + config.json merge
  db.py          SQLite schema, helpers, retention pruning
  metrics.py     CPU/RAM/nvidia-smi sampling, hourly aggregates, per-process GPU counters
  storage.py     home-folder scan, fsutil quota parsing
  events.py      restart history from the System event log
  processes.py   rogue detection, safe termination
  quota.py       policies, evaluation, NTFS enforcement, notifications
  winutil.py     accounts, admin check, WTS sessions, LogonUser, messages, event log
  auth.py        sign-in sessions, role checks, throttling
  scheduler.py   background job threads
  static/        index.html, login.html, app.js, app.css, vendor/chart.umd.min.js
scripts/
  install.ps1  uninstall.ps1  setup-quotas.ps1  make_cert.py
config.example.json  requirements.txt
```
