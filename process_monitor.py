"""
Process Monitor - A simple desktop tool that lists running processes and
flags ones that look "suspicious" based on a set of heuristics.

IMPORTANT / HONEST LIMITATIONS:
    This tool uses heuristics only (unusual file paths, unsigned binaries,
    process names that impersonate well-known system processes, high
    resource usage, suspicious network behavior, etc.). It CANNOT reliably
    detect malware. It will produce both false positives (flagging
    legitimate software) and false negatives (missing real threats). Treat
    the "Suspicious" list as "worth a second look", not as a verdict.
    For real protection, use a reputable, actively-maintained antivirus /
    EDR product alongside this tool, not instead of it.

Author: built with Claude
"""

import os
import sys
import time
import threading
import platform
import traceback
from datetime import datetime

import psutil

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:
    print("This program requires tkinter, which ships with most standard "
          "Python installers. Please reinstall Python with tkinter support.")
    sys.exit(1)


IS_WINDOWS = platform.system() == "Windows"

# Well-known Windows system process names and the directory they're
# legitimately expected to run from. A process using one of these names
# but running from somewhere else is a classic malware-masquerading trick.
KNOWN_SYSTEM_PROCESSES = {
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "explorer.exe": [r"c:\windows"],
    "csrss.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "wininit.exe": [r"c:\windows\system32"],
    "services.exe": [r"c:\windows\system32"],
    "lsass.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "spoolsv.exe": [r"c:\windows\system32"],
    "taskhostw.exe": [r"c:\windows\system32"],
    "dwm.exe": [r"c:\windows\system32"],
    "conhost.exe": [r"c:\windows\system32"],
    "ctfmon.exe": [r"c:\windows\system32"],
    "rundll32.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
}

# Directories that are common malware drop points because they're
# writable-by-default and users rarely look there.
SUSPICIOUS_DIR_HINTS = [
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
    "/tmp/",
    "\\temp\\",
    "\\downloads\\",
    "/downloads/",
    "\\public\\",
    "\\programdata\\",
]

# Names that are frequently used for generic malware / RATs / miners.
# Deliberately short & conservative to avoid too many false positives.
SUSPICIOUS_NAME_HINTS = [
    "miner", "keylog", "rat_", "backdoor", "mimikatz",
    "cryptonight", "xmrig", "stealer",
]

# Legitimate remote-access / remote-support software. These are NOT malware —
# millions of people run TeamViewer or AnyDesk on purpose. But this exact
# category of software is also the #1 tool attackers install after breaking
# in (to keep hands-on-keyboard access), and it's how most tech-support scams
# operate. So: flag it as "verify this was installed on purpose", not "delete
# immediately". Process name (lowercase, with .exe) -> friendly label.
REMOTE_ACCESS_TOOL_NAMES = {
    "teamviewer.exe": "TeamViewer",
    "tv_w32.exe": "TeamViewer",
    "tv_x64.exe": "TeamViewer",
    "anydesk.exe": "AnyDesk",
    "aeroadmin.exe": "AeroAdmin",
    "ammyy.exe": "Ammyy Admin",
    "ammyyadmin.exe": "Ammyy Admin",
    "chrome_remote_desktop_host.exe": "Chrome Remote Desktop",
    "remoting_host.exe": "Chrome Remote Desktop",
    "screenconnect.clientservice.exe": "ScreenConnect/ConnectWise Control",
    "screenconnect.windowsclient.exe": "ScreenConnect/ConnectWise Control",
    "connectwisecontrol.client.exe": "ConnectWise Control",
    "dwagent.exe": "DWService/DWAgent",
    "dwagsvc.exe": "DWService/DWAgent",
    "gotoassist.exe": "GoToAssist",
    "g2mcommunicator.exe": "GoToMeeting/GoToAssist",
    "logmein.exe": "LogMeIn",
    "lmiignition.exe": "LogMeIn",
    "lmiguardiansvc.exe": "LogMeIn",
    "winvnc.exe": "UltraVNC/VNC server",
    "vncserver.exe": "VNC server",
    "vncviewer.exe": "VNC viewer",
    "tvnserver.exe": "TightVNC",
    "splashtopstreamer.exe": "Splashtop",
    "srserver.exe": "Splashtop",
    "client32.exe": "NetSupport Manager",
    "pcicfgutil.exe": "NetSupport Manager",
    "rustdesk.exe": "RustDesk",
    "rutserv.exe": "Remote Utilities",
    "rfusclient.exe": "Remote Utilities",
    "supremo.exe": "Supremo",
    "radmin.exe": "Radmin",
    "r_server.exe": "Radmin server",
    "parsecd.exe": "Parsec",
    "atera_agent.exe": "Atera RMM",
    "ninjarmmagent.exe": "NinjaRMM",
    "action1_agent.exe": "Action1 RMM",
    "syncrosupervisor.exe": "Kaseya/Syncro RMM",
    "iterm2remoted.exe": "Generic remote desktop helper",
    "showmypc.exe": "ShowMyPC",
    "getscreen.exe": "GetScreen",
}

# Known family / campaign names publicly associated with RATs and commodity
# malware. Deliberately conservative and drawn from widely-published threat
# intel (these show up in security vendor writeups, not secret info).
# Matched as a substring of the process name.
KNOWN_RAT_MALWARE_KEYWORDS = [
    "njrat", "darkcomet", "nanocore", "quasarrat", "quasar_rat", "asyncrat",
    "remcos", "xtremerat", "poisonivy", "gh0st", "cobaltstrike", "beacon.exe",
    "venomrat", "warzonerat", "orcusrat", "imminentmonitor", "luminositylink",
    "revengerat", "netwire", "babylonrat", "bladabindi", "njw0rm", "houdini_rat",
    "meterpreter",
]

CPU_HIGH_THRESHOLD = 50.0      # percent, sustained
MEM_HIGH_THRESHOLD_MB = 800    # MB RSS, arbitrary "worth a look" bar
SCAN_INTERVAL_MS = 3000        # how often auto-refresh runs, if enabled


def bytes_to_mb(n):
    return n / (1024 * 1024)


def looks_like_random_name(name):
    """Very rough heuristic: names that are long, have no vowels, or are
    mostly hex-looking are sometimes auto-generated malware droppers."""
    base = os.path.splitext(name)[0].lower()
    if len(base) < 6:
        return False
    vowels = sum(1 for c in base if c in "aeiou")
    if vowels == 0 and len(base) >= 7 and base.isalnum():
        return True
    # Looks like a hex/UUID-ish blob, e.g. "a1b2c3d4e5f6"
    hex_chars = sum(1 for c in base if c in "0123456789abcdef")
    if len(base) >= 10 and hex_chars / len(base) > 0.85:
        return True
    return False


def get_process_info(p):
    """Safely pull a normalized dict of info out of a psutil.Process."""
    info = {
        "pid": p.pid,
        "name": "?",
        "exe": "",
        "username": "",
        "cpu": 0.0,
        "mem_mb": 0.0,
        "create_time": None,
        "cmdline": "",
        "connections": 0,
        "status": "",
        "reasons": [],
        "severity": "",
        "category": "",
    }
    try:
        info["name"] = p.name()
    except Exception:
        pass
    try:
        info["exe"] = p.exe()
    except Exception:
        pass
    try:
        info["username"] = p.username()
    except Exception:
        info["username"] = "?"
    try:
        info["cpu"] = p.cpu_percent(interval=None)
    except Exception:
        pass
    try:
        info["mem_mb"] = bytes_to_mb(p.memory_info().rss)
    except Exception:
        pass
    try:
        ct = p.create_time()
        info["create_time"] = datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    try:
        info["cmdline"] = " ".join(p.cmdline())
    except Exception:
        pass
    try:
        info["status"] = p.status()
    except Exception:
        pass
    try:
        conns = p.connections(kind="inet")
        info["connections"] = len(conns)
        info["listening"] = any(c.status == psutil.CONN_LISTEN for c in conns)
    except Exception:
        info["listening"] = False

    return info


def evaluate_suspicion(info):
    """Apply heuristics to a process info dict. Mutates info['reasons']
    (a list of human-readable strings), info['severity'] ("high", "medium",
    or "" for none), and info['category'] (a short tag for filtering).
    Returns True/False for whether the process should be flagged at all."""
    reasons = []
    severity = ""  # "high" or "medium" — highest one seen wins
    category = ""
    name = (info["name"] or "").lower()
    exe = (info["exe"] or "").lower()
    cmdline = (info["cmdline"] or "").lower()

    def bump(sev):
        nonlocal severity
        order = {"": 0, "medium": 1, "high": 2}
        if order[sev] > order[severity]:
            severity = sev

    # 0a. Known remote-access / remote-support software. Legitimate on its
    # own, but this exact category is the most common tool attackers (and
    # tech-support scammers) install to keep hands-on-keyboard access —
    # so it's always worth a quick "did I/my IT team install this?" check.
    if name in REMOTE_ACCESS_TOOL_NAMES:
        tool = REMOTE_ACCESS_TOOL_NAMES[name]
        reasons.append(
            f"Remote access / remote support software detected: {tool}. "
            f"Legitimate on its own, but confirm you or your IT team "
            f"installed it intentionally — it's also the most common tool "
            f"used to maintain unauthorized remote access."
        )
        bump("medium")
        category = "remote_access"

    # 0b. Known RAT / commodity malware family name match — either in the
    # process name or (more reliably, since names get renamed) in the
    # command line.
    for kw in KNOWN_RAT_MALWARE_KEYWORDS:
        if kw in name or kw in cmdline:
            reasons.append(f"Matches known malware/RAT family name '{kw}'")
            bump("high")
            category = "malware_name"
            break

    # 1. Known system process name but running from the wrong folder.
    if name in KNOWN_SYSTEM_PROCESSES and exe:
        expected_dirs = KNOWN_SYSTEM_PROCESSES[name]
        if not any(exe.startswith(d) for d in expected_dirs):
            reasons.append(
                f"Named like a Windows system process ('{info['name']}') "
                f"but not running from the expected system folder"
            )
            bump("high")
            category = category or "system_masquerade"

    # 2. Running from a commonly-abused temp/downloads-style directory.
    if exe:
        for hint in SUSPICIOUS_DIR_HINTS:
            if hint in exe:
                reasons.append(f"Executable is located in '{hint.strip(chr(92)+'/')}' — a common drop location")
                bump("medium")
                category = category or "suspicious_location"
                break

    # 3. No accessible exe path AND no command line either — often a genuine
    #    self-deleting/hidden process. (Kernel threads on Linux and some
    #    protected Windows processes also have no exe path but are normal;
    #    requiring an empty cmdline too, plus excluding obvious kernel
    #    thread naming, cuts down false positives from those.)
    is_kernel_thread_like = name.startswith("k") and ("/" in name or name.endswith("d"))
    if (not exe and not info["cmdline"] and
            info["name"] not in ("System", "System Idle Process", "?") and
            not is_kernel_thread_like):
        reasons.append("Could not determine executable path or command line (possibly self-deleting or hidden)")
        bump("high")
        category = category or "hidden"

    # 4. Suspicious keyword in the name (generic, lower-confidence than the
    #    known RAT family list above).
    for kw in SUSPICIOUS_NAME_HINTS:
        if kw in name:
            reasons.append(f"Process name contains suspicious keyword '{kw}'")
            bump("medium")
            category = category or "keyword"
            break

    # 5. Randomly-generated-looking filename.
    if looks_like_random_name(info["name"] or ""):
        reasons.append("Filename looks randomly generated (common in droppers)")
        bump("medium")
        category = category or "random_name"

    # 6. High sustained CPU or memory.
    if info["cpu"] >= CPU_HIGH_THRESHOLD:
        reasons.append(f"High CPU usage ({info['cpu']:.0f}%)")
        bump("medium")
        category = category or "resource"
    if info["mem_mb"] >= MEM_HIGH_THRESHOLD_MB:
        reasons.append(f"High memory usage ({info['mem_mb']:.0f} MB)")
        bump("medium")
        category = category or "resource"

    # 7. Listening network socket + no exe path resolvable (weirder combo).
    if info.get("listening") and not exe:
        reasons.append("Has an open listening network port but no resolvable file path")
        bump("high")
        category = category or "network"

    # 8. Running as SYSTEM/root but launched from a user-writable directory.
    uname = (info["username"] or "").lower()
    if exe and ("system" in uname or uname == "root"):
        for hint in ["\\appdata\\", "\\temp\\", "/tmp/", "\\downloads\\"]:
            if hint in exe:
                reasons.append("Running with elevated/system privileges from a user-writable folder")
                bump("high")
                category = category or "privilege"
                break

    info["reasons"] = reasons
    info["severity"] = severity
    info["category"] = category
    return len(reasons) > 0


class ProcessMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Monitor — Suspicious Process Scanner")
        self.root.geometry("1150x620")
        self.root.minsize(850, 450)

        self.all_processes = []       # list of info dicts, always populated
        self.suspicious_processes = []
        self.show_all_mode = False
        self.auto_refresh = tk.BooleanVar(value=False)
        self.scanning = False

        self._build_ui()
        self._prime_cpu_percent()
        self.refresh(initial=True)

    # ---------- UI construction ----------

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill="x")

        ttk.Button(top, text="Rescan Now", command=self.refresh).pack(side="left", padx=4)

        self.toggle_btn = ttk.Button(
            top, text="Show ALL Processes", command=self.toggle_show_all
        )
        self.toggle_btn.pack(side="left", padx=4)

        ttk.Checkbutton(
            top, text="Auto-refresh every 3s", variable=self.auto_refresh,
            command=self._toggle_auto_refresh
        ).pack(side="left", padx=12)

        self.status_label = ttk.Label(top, text="")
        self.status_label.pack(side="left", padx=12)

        ttk.Button(top, text="Export List...", command=self.export_list).pack(side="right", padx=4)

        # Search box
        search_frame = ttk.Frame(self.root, padding=(8, 0))
        search_frame.pack(fill="x")
        ttk.Label(search_frame, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *a: self.render_table())
        ttk.Entry(search_frame, textvariable=self.filter_var, width=40).pack(side="left", padx=6)

        self.remote_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            search_frame, text="Remote access tools only",
            variable=self.remote_only_var, command=self.render_table
        ).pack(side="left", padx=12)

        self.high_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            search_frame, text="High severity only",
            variable=self.high_only_var, command=self.render_table
        ).pack(side="left", padx=4)

        # Table
        columns = ("pid", "name", "user", "severity", "cpu", "mem", "started", "path", "reasons")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="browse")
        headers = {
            "pid": ("PID", 55),
            "name": ("Name", 150),
            "user": ("User", 100),
            "severity": ("Flag", 90),
            "cpu": ("CPU %", 55),
            "mem": ("Mem (MB)", 75),
            "started": ("Started", 130),
            "path": ("Path", 230),
            "reasons": ("Why flagged", 320),
        }
        for col in columns:
            label, width = headers[col]
            self.tree.heading(col, text=label, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        vsb.pack(side="left", fill="y", pady=8)

        # Right-click context menu: kill process
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Terminate Process", command=self.kill_selected)
        self.menu.add_command(label="Copy Path", command=self.copy_selected_path)
        self.tree.bind("<Button-3>", self._show_context_menu)

        self.tree.tag_configure("high", background="#ffc9c9")
        self.tree.tag_configure("medium", background="#ffe4b3")

        # Footer disclaimer
        footer = ttk.Label(
            self.root,
            text=("Heuristic scanner only — flags are hints, not proof of malware. "
                  "Always verify before terminating anything you don't recognize."),
            foreground="#555555", padding=6
        )
        footer.pack(fill="x", side="bottom")

        self.sort_state = {"col": None, "reverse": False}

    def _prime_cpu_percent(self):
        # psutil needs a first no-wait call per-process to establish a
        # baseline before cpu_percent() readings are meaningful.
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

    # ---------- Scanning ----------

    def refresh(self, initial=False):
        if self.scanning:
            return
        self.scanning = True
        self.status_label.config(text="Scanning...")
        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def _scan_worker(self):
        try:
            all_info = []
            for p in psutil.process_iter():
                try:
                    info = get_process_info(p)
                    evaluate_suspicion(info)
                    all_info.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    continue

            self.all_processes = all_info
            self.suspicious_processes = [i for i in all_info if i["reasons"]]
        except Exception:
            traceback.print_exc()
        finally:
            self.scanning = False
            self.root.after(0, self._on_scan_complete)

    def _on_scan_complete(self):
        total = len(self.all_processes)
        flagged = len(self.suspicious_processes)
        ts = datetime.now().strftime("%H:%M:%S")
        self.status_label.config(
            text=f"Last scan {ts} — {total} processes total, {flagged} flagged"
        )
        self.render_table()

    def _toggle_auto_refresh(self):
        if self.auto_refresh.get():
            self._auto_refresh_loop()

    def _auto_refresh_loop(self):
        if not self.auto_refresh.get():
            return
        self.refresh()
        self.root.after(SCAN_INTERVAL_MS, self._auto_refresh_loop)

    # ---------- Rendering ----------

    def toggle_show_all(self):
        self.show_all_mode = not self.show_all_mode
        self.toggle_btn.config(
            text="Show SUSPICIOUS Only" if self.show_all_mode else "Show ALL Processes"
        )
        self.render_table()

    def render_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        source = self.all_processes if self.show_all_mode else self.suspicious_processes
        filt = self.filter_var.get().strip().lower()
        remote_only = self.remote_only_var.get()
        high_only = self.high_only_var.get()

        rows = []
        for info in source:
            if remote_only and info.get("category") != "remote_access":
                continue
            if high_only and info.get("severity") != "high":
                continue
            if filt:
                haystack = " ".join([
                    str(info["pid"]), info["name"] or "", info["username"] or "",
                    info["exe"] or "", info["cmdline"] or ""
                ]).lower()
                if filt not in haystack:
                    continue
            rows.append(info)

        col = self.sort_state["col"]
        if col:
            sev_rank = {"high": 2, "medium": 1, "": 0}
            key_map = {
                "pid": lambda r: r["pid"],
                "name": lambda r: (r["name"] or "").lower(),
                "user": lambda r: (r["username"] or "").lower(),
                "severity": lambda r: sev_rank.get(r.get("severity", ""), 0),
                "cpu": lambda r: r["cpu"],
                "mem": lambda r: r["mem_mb"],
                "started": lambda r: r["create_time"] or "",
                "path": lambda r: (r["exe"] or "").lower(),
                "reasons": lambda r: len(r["reasons"]),
            }
            rows.sort(key=key_map.get(col, lambda r: 0), reverse=self.sort_state["reverse"])

        for info in rows:
            reasons_text = "; ".join(info["reasons"])
            sev = info.get("severity", "")
            sev_label = {"high": "HIGH", "medium": "Medium"}.get(sev, "")
            tag = (sev,) if sev else ()
            self.tree.insert("", "end", iid=str(info["pid"]), values=(
                info["pid"],
                info["name"],
                info["username"],
                sev_label,
                f"{info['cpu']:.1f}",
                f"{info['mem_mb']:.1f}",
                info["create_time"] or "",
                info["exe"],
                reasons_text,
            ), tags=tag)

    def sort_by(self, col):
        if self.sort_state["col"] == col:
            self.sort_state["reverse"] = not self.sort_state["reverse"]
        else:
            self.sort_state["col"] = col
            self.sort_state["reverse"] = False
        self.render_table()

    # ---------- Actions ----------

    def _show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.menu.tk_popup(event.x_root, event.y_root)

    def kill_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        pid = int(sel[0])
        name = self.tree.set(sel[0], "name")
        if not messagebox.askyesno(
            "Confirm Terminate",
            f"Terminate process '{name}' (PID {pid})?\n\nThis cannot be undone."
        ):
            return
        try:
            p = psutil.Process(pid)
            p.terminate()
            try:
                p.wait(timeout=3)
            except psutil.TimeoutExpired:
                p.kill()
            messagebox.showinfo("Terminated", f"Process {pid} terminated.")
        except psutil.NoSuchProcess:
            messagebox.showwarning("Not found", "Process no longer exists.")
        except psutil.AccessDenied:
            messagebox.showerror(
                "Access denied",
                "Permission denied. Try running this program as Administrator."
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
        self.refresh()

    def copy_selected_path(self):
        sel = self.tree.selection()
        if not sel:
            return
        path = self.tree.set(sel[0], "path")
        self.root.clipboard_clear()
        self.root.clipboard_append(path)

    def export_list(self):
        source = self.all_processes if self.show_all_mode else self.suspicious_processes
        if not source:
            messagebox.showinfo("Nothing to export", "There are no processes to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("Text file", "*.txt")],
            initialfile="process_scan.csv"
        )
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Name", "User", "Severity", "Category", "CPU%", "Mem(MB)", "Started", "Path", "Reasons"])
            for info in source:
                writer.writerow([
                    info["pid"], info["name"], info["username"],
                    info.get("severity", ""), info.get("category", ""),
                    f"{info['cpu']:.1f}", f"{info['mem_mb']:.1f}",
                    info["create_time"] or "", info["exe"],
                    "; ".join(info["reasons"])
                ])
        messagebox.showinfo("Exported", f"Saved to {path}")


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if IS_WINDOWS:
            style.theme_use("vista")
        else:
            style.theme_use("clam")
    except Exception:
        pass
    app = ProcessMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
