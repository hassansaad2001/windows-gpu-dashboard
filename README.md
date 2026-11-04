# AI Server Dashboard

A self-hosted web dashboard for a **shared, multi-user Windows Server** that runs AI and GPU
workloads: lab servers, small render or training boxes, or any machine many people reach over RDP.
It runs as a Windows service and needs no agent, no domain and no internet access once installed.

## Features

- **Live and historical load:** CPU, RAM and per-GPU utilization, memory, temperature and power
  (NVIDIA, through `nvidia-smi`). Samples every minute and keeps hourly history for two years.
- **Who is using the GPUs:** per-process VRAM and GPU usage from Windows' WDDM performance counters,
  which works on GeForce cards where `nvidia-smi` can't attribute memory. CUDA jobs inside WSL2 are
  charged to the user who started the VM.
- **Rogue-process detection:** finds orphaned jobs (owner signed out), detached jobs, idle
  disconnected sessions, multi-GPU hogs and long runs. Admins can end a process tree (with PID-reuse
  protection) or log off a session. WSL VMs are never killed, because that can corrupt the Linux disk.
- **Storage:** home-folder sizes per user and NTFS per-owner usage, with daily history.
- **Storage quotas:** NTFS quota policies per user or for all users: *soft* (warn), *hard*, or
  *soft + grace period, then block*. Users get pop-up warnings, and events go to the event log.
  A preview shows who a policy would block before you save it.
  [Safety rules](DEPLOYMENT.md#safety-rules) protect WSL/Docker disks, admins and service accounts.
- **Restart history:** planned restarts with who and why, crashes with bugcheck codes, power
  failures with outage length, read from the System event log and kept beyond its retention.
- **Windows sign-in:** users sign in with their local Windows account. Administrators get the
  admin actions, everyone else gets read-only access, and sign-in can be limited to listed accounts.
  Every sign-in and admin action is written to an audit log.

## Requirements

- Windows Server with NTFS volumes. Tested on Windows Server 2022; it uses only standard
  Windows APIs, so 2019, 2025 and Windows 10/11 should work but are untested.
- Python 3.10+ installed **for all users** from [python.org](https://www.python.org/downloads/windows/)
- Administrator rights to install
- Optional: an NVIDIA driver with `nvidia-smi` on PATH, for GPU metrics

## Quick start

From an **elevated** PowerShell:

```powershell
git clone https://github.com/<you>/<this-repo>.git
cd <this-repo>
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

Then open `https://<server-name>:8443` from a computer on the same network and sign in with a
Windows account on the server. The certificate is self-signed, so the browser warns once.

The installer copies the app to `C:\AIDashboard`, creates a virtual environment, makes a TLS
certificate, registers the `AIDashboard` service with [NSSM](https://nssm.cc), opens TCP 8443
for the local subnet only, and enlarges the System event log. Re-running it upgrades in place and
keeps your settings and data.

Settings live in `C:\AIDashboard\config.json`; see [`config.example.json`](config.example.json)
and the full [deployment guide](DEPLOYMENT.md).

## Security notes

- Keep HTTPS on: users type their Windows passwords into the sign-in form.
- The firewall rule admits the local subnet only. Don't expose port 8443 to the internet; for
  remote access, use a VPN or an overlay network such as Tailscale
  ([how](DEPLOYMENT.md#remote-access-optional)).
- The service runs as LocalSystem, because it has to read and end other users' processes and
  manage quotas. The install folder is readable only by Administrators and SYSTEM.
- The installed files are read-only for every account, Administrators included. The service
  checks them against a SHA-256 baseline and alerts if any file changes, and the Security event
  log records who changed it ([details](DEPLOYMENT.md#file-protection)).
- `config.json`, the database, logs and certificates hold server-specific data and are
  git-ignored. Don't commit them.

## Uninstall

```powershell
C:\AIDashboard\scripts\uninstall.ps1               # remove the service and firewall rule
C:\AIDashboard\scripts\uninstall.ps1 -RemoveFiles  # also delete C:\AIDashboard and its data
```

Uninstalling lifts every quota limit the dashboard set, so nobody stays blocked.

## License

[MIT](LICENSE). Bundled Chart.js is MIT too; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
