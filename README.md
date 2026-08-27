# Process Monitor

> ⚠️ **This is vibecoded.** This project was built almost entirely by prompting an AI assistant (Claude), with light human review, not written from scratch by a security engineer. It has **not** been audited, pen-tested, or reviewed by a professional. Read the code before you run it, especially anything involving process termination or admin privileges. Use at your own risk, and don't treat this as a substitute for real security software.

A small Windows desktop app that scans your running processes, flags ones that look **heuristically suspicious** — with a special eye on remote access software and known malware/RAT naming patterns — and lets you toggle to see the full list of every process on your machine.

**note for some reason downloading the src from the release doesn't work and idk how to fix it so just download the py file and the requirements.txt file if you wanna run from the source**

---

## ⚠️ What this actually is (please read)

This is a **heuristic scanner**, not an antivirus engine, not an EDR product, and not a substitute for one. It cannot reliably detect malware — it can only pattern-match against known bad habits. It **will** have:

- **False positives** — flagging legitimate software that happens to live in an unusual folder or use a lot of memory.
- **False negatives** — missing real malware that doesn't match these specific patterns. A determined attacker can trivially rename a file to dodge name-based checks.

Treat every flag as *"worth a second look,"* never as a verdict. Pair this with a real, actively-maintained antivirus/EDR product — don't use it instead of one.

---

## What it flags

| Category | Severity | What it means |
|---|---|---|
| **Known remote access / remote support software** (TeamViewer, AnyDesk, ScreenConnect, LogMeIn, VNC variants, RustDesk, Splashtop, NetSupport, common RMM agents) | 🟠 Medium | Legitimate tools on their own — but also the #1 thing attackers install to keep access after a breach, and how most tech-support scams work. Flag just means: *confirm you or your IT team installed this on purpose.* |
| **Known RAT / commodity malware family name match** (njRAT, DarkComet, NanoCore, AsyncRAT, Remcos, QuasarRAT, Cobalt Strike beacon, Meterpreter, etc.) | 🔴 High | Process name or command line matches a publicly-documented malware family name. |
| **System process name in the wrong folder** (e.g. `svchost.exe` not in `System32`) | 🔴 High | Classic malware-masquerading trick. |
| **No resolvable executable path or command line** | 🔴 High | Can indicate a self-deleting or hidden dropper. |
| **Elevated/SYSTEM process launched from a user-writable folder** | 🔴 High | Privilege + an unusual launch location. |
| **Listening network port with no resolvable executable** | 🔴 High | Unusual combination worth investigating. |
| **Running from a commonly-abused location** (`%TEMP%`, `AppData\Roaming`, `Downloads`, `ProgramData`) | 🟠 Medium | Common drop points for malware, but plenty of legitimate installers use them too. |
| **Suspicious keyword in name** (miner, keylogger, stealer, etc.) | 🟠 Medium | Low-confidence generic keyword match. |
| **Randomly-generated-looking filename** | 🟠 Medium | Common in auto-generated droppers. |
| **Sustained high CPU / memory usage** | 🟠 Medium | Could be anything — a game, a build process, or something worth a look. |

## Features

- **Suspicious view** (default) — only shows flagged processes with the reason(s) they were flagged, color-coded by severity.
- **"Show ALL Processes"** button — toggles to the complete process list.
- **"Remote access tools only"** filter — isolate just that category.
- **"High severity only"** filter — cut the medium-confidence noise.
- Search/filter box, sortable columns.
- Right-click a process to **terminate** it or **copy its path**.
- **Export** the current view to CSV (includes severity + category).
- Optional auto-refresh every 3 seconds.


## Installation & running from source

Requires **Python 3.8+** with Tk support (bundled with the official python.org installers for Windows/macOS; on Linux, `sudo apt install python3-tk`).

```bash
git clone https://github.com/yesyfhhf/Process-Monitor-terrible-edition.git
cd Process-Monitor-terrible-edition
pip install -r requirements.txt
python process_monitor.py
```

## Building a standalone .exe

PyInstaller builds for whatever OS it's running on — **build this on an actual Windows machine** if you want a Windows `.exe` (no cross-compiling from Linux/macOS).

```bash
pip install -r requirements.txt
python -m PyInstaller --onefile --windowed --name ProcessMonitor process_monitor.py
```

- `--onefile` bundles everything into a single `ProcessMonitor.exe`.
- `--windowed` suppresses the console window (this is a GUI app).
- Output lands in `dist/ProcessMonitor.exe`.

Optional:
- Add an icon: `--icon=youricon.ico`
- If Windows Defender/SmartScreen flags the freshly-built exe, that's a common false positive against unsigned PyInstaller binaries (especially ones that enumerate processes) — not necessarily a sign anything's wrong. Code-sign it if you plan to distribute it.

### Administrator privileges

Some process details (full path, owner, terminating other users' processes) require elevated privileges. Right-click → "Run as administrator" for full visibility.

## Project structure

```
.
├── process_monitor.py   # entire application, single file
├── requirements.txt     # psutil (runtime) + pyinstaller (packaging)
└── README.md
```

## Contributing

This started as an AI-assisted prototype, so there's plenty of room for real scrutiny — better heuristics, reduced false positives, code-signing checks (via `pywin32`/Authenticode), actual hash/reputation lookups, tests, etc. PRs and issues welcome.


## Disclaimer

Provided as-is, with no warranty. Terminating the wrong process can crash your system or lose unsaved work — double-check before you kill anything you don't recognize. Not a replacement for real antivirus/EDR software.
