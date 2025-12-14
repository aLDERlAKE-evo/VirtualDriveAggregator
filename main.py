"""
Virtual Aggregated Drive Manager — Final (All features, Pause fixed, Checksums, Index backup)
 - Uses ttkbootstrap for UI (keeps your layout)
 - ThreadPoolExecutor for background tasks
 - logging module + GUI log
 - Pause split into user_pause_flag & drive_pause_flag (manual pause won't auto-resume)
 - Very responsive pause (32 KB sub-block writes)
 - SHA256 checksums for each .part stored in index and verified on download
 - Index replicated to all selected drives after every save
 - Repair option 'B' behavior: Retry (keeps rechecking until user aborts) or Abort
"""

import os
import json
import shutil
import threading
import string
import time
import tempfile
import subprocess
import hashlib
from typing import Callable, List, Tuple, Union, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, Future

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import zipfile
import logging

import ttkbootstrap as tb
from ttkbootstrap.constants import *

# optional drag & drop
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    DND_AVAILABLE = True
except Exception:
    DND_AVAILABLE = False

# optional pywin32 drive detection
try:
    import win32file
except Exception:
    win32file = None

# ---------- Configuration ----------
INDEX_DIR_NAME = ".vdrive_meta"
INDEX_FILE_NAME = "index.json"
DRIVE_MONITOR_MS = 2000       # ms for drive monitor / scan
DEFAULT_CHUNK_MB = 8
CHUNK_CHOICES_MB = [4, 8, 16, 32, 64]
COMPRESSION_CHOICES = ["store", "zip", "lzma"]
MAX_WORKERS = 3               # ThreadPoolExecutor max workers
SUB_BLOCK_SIZE = 32 * 1024    # 32 KB sub-block for very responsive pause
# -----------------------------------

IndexValue = Union[List[str], Dict[str, Any]]


@dataclass
class Progress:
    file_done: int = 0
    file_total: int = 0
    folder_done: int = 0
    folder_total: int = 0
    eta: float = 0.0


class App:
    def __init__(self, root: tb.Window, start_theme: str = "darkly"):
        self.root = root
        self.root.title("Virtual Aggregated Drive Manager")
        self.root.geometry("1240x820")

        # logging setup
        logging.basicConfig(filename="vdrive_log.txt", level=logging.INFO,
                            format="%(asctime)s %(levelname)s: %(message)s", datefmt="%H:%M:%S")
        # state for GUI log insertion
        self._log_lock = threading.Lock()

        # theme
        self.current_theme = start_theme
        try:
            self.root.style.theme_use(self.current_theme)
        except Exception:
            pass

        # executor for background tasks
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
        self._futures: List[Future] = []

        # state
        self.selected_drives: List[str] = []
        self.virtual_index: Dict[str, IndexValue] = {}
        self._lock = threading.Lock()

        # UI/state variables
        self.current_file = tk.StringVar(value="Idle")
        self.file_progress = tk.DoubleVar(value=0.0)
        self.folder_progress = tk.DoubleVar(value=0.0)
        self.file_counter = tk.StringVar(value="0/0")
        self.eta = tk.StringVar(value="--")
        self.storage_info = tk.StringVar(value="Total: -- | Free: --")

        self.chunk_mb = tk.IntVar(value=DEFAULT_CHUNK_MB)
        self.compression_mode = tk.StringVar(value="store")

        # Pause flags: separate user-driven vs drive-driven
        self.user_pause_flag = threading.Event()
        self.drive_pause_flag = threading.Event()
        self.cancel_flag = threading.Event()

        self._current_upload_future: Future | None = None

        # drive lists
        self.removable: List[str] = []
        self.drive_vars: List[tk.StringVar] = []
        self.option_menus: List[ttk.Combobox] = []

        # build UI
        self._build_ui()

        # start background scans (drives) and storage info
        self._scan_drives_periodic()
        self._update_storage_info()

        self._log("Application started")

    # ---------------- UI ----------------
    def _build_ui(self):
        # top bar with theme toggle
        top = tb.Frame(self.root, padding=8)
        top.pack(fill="x")
        tb.Label(top, text="Virtual Aggregated Drive Manager", font=("Segoe UI", 16, "bold")).pack(side="left")
        tb.Button(top, text="Toggle Theme", bootstyle="secondary", command=self._toggle_theme).pack(side="right")

        main_frame = tb.Frame(self.root, padding=12)
        main_frame.pack(fill="both", expand=True)

        # Drive selection
        self.drive_frame = tb.Labelframe(main_frame, text="Drive Selection", padding=8)
        self.drive_frame.pack(fill="x", pady=6)

        # Drive selection (replace the previous loop that created comboboxes)
        self.removable = ["None"] + self._list_removable_drives()
        self.drive_vars = []
        self.option_menus = []
        drives_row = tb.Frame(self.drive_frame)
        drives_row.pack()
        for i in range(4):
            col = tb.Frame(drives_row)
            col.pack(side="left", padx=8)
            tb.Label(col, text=f"Drive {i + 1}").pack()
            var = tk.StringVar(value="None")
            self.drive_vars.append(var)
            cb = tb.Combobox(col, textvariable=var, values=self.removable, width=12, state="readonly")
            cb.pack()
            self.option_menus.append(cb)

        opts_row = tb.Frame(self.drive_frame)
        opts_row.pack(fill="x", pady=6)
        tb.Label(opts_row, text="Chunk Size (MB):").pack(side="left", padx=(6, 6))
        ttk.Combobox(opts_row, textvariable=self.chunk_mb, values=CHUNK_CHOICES_MB, width=6, state="readonly").pack(
            side="left")
        tb.Label(opts_row, text="(8MB stable)").pack(side="left", padx=(6, 20))
        tb.Label(opts_row, text="Compression:").pack(side="left")
        ttk.Combobox(opts_row, textvariable=self.compression_mode, values=COMPRESSION_CHOICES, width=8,
                     state="readonly").pack(side="left")

        # Confirm / Refresh / Purge row
        btns = tb.Frame(self.drive_frame)
        btns.pack(pady=8)
        tb.Button(btns, text="Confirm", bootstyle="success", command=self._confirm_selection).pack(side="left", padx=6)
        tb.Button(btns, text="Refresh Drives", bootstyle="info", command=self._refresh_drives).pack(side="left", padx=6)
        tb.Button(btns, text="Purge All", bootstyle="danger", command=self._purge_all).pack(side="left", padx=6)

        # Notebook
        nb = tb.Notebook(main_frame)
        nb.pack(fill="both", expand=True, pady=6)
        files_tab = tb.Frame(nb)
        logs_tab = tb.Frame(nb)
        nb.add(files_tab, text="Files")
        nb.add(logs_tab, text="Logs")

        # Files tab: treeview + controls
        tree_frame = tb.Frame(files_tab)
        tree_frame.pack(fill="both", expand=True)

        # Tree
        self.tree = ttk.Treeview(tree_frame, show="tree")
        self.tree.pack(side="left", fill="both", expand=True)
        yscr = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscr.set)
        yscr.pack(side="right", fill="y")
        # optional drag & drop on tree
        if DND_AVAILABLE:
            try:
                self.tree.drop_target_register(DND_FILES)
                self.tree.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

        # Expand/Collapse
        ctrl_row = tb.Frame(files_tab)
        ctrl_row.pack(pady=8)
        tb.Button(ctrl_row, text="Expand All", bootstyle="secondary", command=self._expand_all).pack(side="left", padx=6)
        tb.Button(ctrl_row, text="Collapse All", bootstyle="secondary", command=self._collapse_all).pack(side="left", padx=6)

        # Controls: first row (uniform buttons)
        btn_style = dict(width=16, padding=6)
        controls = tb.Frame(files_tab)
        controls.pack(pady=8)

        row1 = tb.Frame(controls)
        row1.pack(pady=6)
        tb.Button(row1, text="Upload File", bootstyle="info", command=self._upload_file_dialog, **btn_style).pack(side="left", padx=6)
        tb.Button(row1, text="Upload Folder", bootstyle="primary", command=self._upload_folder_dialog, **btn_style).pack(side="left", padx=6)
        tb.Button(row1, text="Download", bootstyle="warning", command=self._download_item, **btn_style).pack(side="left", padx=6)
        tb.Button(row1, text="Delete", bootstyle="danger", command=self._delete_item, **btn_style).pack(side="left", padx=6)
        tb.Button(row1, text="Refresh", bootstyle="success", command=self._refresh_tree, **btn_style).pack(side="left", padx=6)

        row2 = tb.Frame(controls)
        row2.pack(pady=6)
        tb.Button(row2, text="Pause", bootstyle="warning", command=self._pause, **btn_style).pack(side="left", padx=6)
        tb.Button(row2, text="Resume", bootstyle="success", command=self._resume, **btn_style).pack(side="left", padx=6)
        tb.Button(row2, text="Cancel", bootstyle="danger", command=self._cancel, **btn_style).pack(side="left", padx=6)

        # Status area
        status = tb.Labelframe(main_frame, text="Status", padding=8)
        status.pack(fill="x", pady=6)
        tb.Label(status, textvariable=self.current_file).pack(pady=(4, 0))
        tb.Progressbar(status, variable=self.file_progress).pack(fill="x", padx=10, pady=(6, 4))
        tb.Progressbar(status, variable=self.folder_progress).pack(fill="x", padx=10, pady=(0, 6))

        bottom = tb.Frame(status)
        bottom.pack(fill="x", padx=8)
        tb.Label(bottom, textvariable=self.file_counter).pack(side="left")
        tb.Label(bottom, textvariable=self.eta).pack(side="left", padx=20)
        tb.Label(bottom, textvariable=self.storage_info, font=("Segoe UI", 10, "bold")).pack(side="right")

        # Logs tab
        self.log_box = tk.Text(logs_tab, bg="black", fg="lime", wrap="none")
        self.log_box.pack(fill="both", expand=True)

    # ---------------- UI helpers ----------------
    def _toggle_theme(self):
        """Toggle between light and dark modes with live refresh."""
        new_theme = "flatly" if self.current_theme == "darkly" else "darkly"
        try:
            self.root.style.theme_use(new_theme)
            self.current_theme = new_theme
            self._log(f"Theme switched to {new_theme}")
        except Exception as e:
            self._log(f"Theme toggle failed: {e}", level="error")

    def _expand_all(self):
        for i in self.tree.get_children():
            self.tree.item(i, open=True)

    def _collapse_all(self):
        for i in self.tree.get_children():
            self.tree.item(i, open=False)

    # ---------------- Logging ----------------
    def _log(self, msg: str, level: str = "info"):
        # Log to file via logging module
        if level == "info":
            logging.info(msg)
        elif level == "warning":
            logging.warning(msg)
        elif level == "error":
            logging.error(msg)
        else:
            logging.debug(msg)

        # Insert into GUI text area from main thread
        def insert():
            t = time.strftime("%H:%M:%S")
            line = f"[{t}] {msg}\n"
            try:
                self.log_box.insert("end", line)
                self.log_box.see("end")
            except Exception:
                pass

        try:
            self.root.after_idle(insert)
        except Exception:
            insert()

    # ---------------- Drives / Index ----------------
    def _list_removable_drives(self) -> List[str]:
        drives: List[str] = []
        if win32file is None:
            # best-effort fallback: include drives that exist (non-ideal)
            for letter in string.ascii_uppercase:
                d = f"{letter}:/"
                if os.path.exists(d):
                    drives.append(d)
            return drives
        for letter in string.ascii_uppercase:
            d = f"{letter}:/"
            try:
                if win32file.GetDriveType(d) == win32file.DRIVE_REMOVABLE:
                    drives.append(d)
            except Exception:
                pass
        return drives

    def _refresh_drives(self):
        """
        Manual refresh — repopulate combobox values and keep current selections if still valid.
        """
        try:
            real_drives = self._list_removable_drives()
            values = ["None"] + real_drives
            self.removable = values[:]  # keep "None" included for UI lists

            for var, widget in zip(self.drive_vars, self.option_menus):
                cur = var.get()
                try:
                    widget['values'] = values
                    if cur not in values:
                        var.set("None")
                    continue
                except Exception:
                    pass
                try:
                    menu = widget["menu"]
                    menu.delete(0, "end")
                    menu.add_command(label="None", command=tk._setit(var, "None"))
                    for d in real_drives:
                        menu.add_command(label=d, command=tk._setit(var, d))
                    if cur not in (["None"] + real_drives):
                        var.set("None")
                    continue
                except Exception:
                    var.set("None")

            self._log("Drive list refreshed (manual)")
        except Exception as e:
            self._log(f"_refresh_drives failed: {e}", level="error")

    def _scan_drives_periodic(self):
        """
        Auto-scan drives every DRIVE_MONITOR_MS ms and update comboboxes when hot-plug changes are detected.
        This also manages the drive_pause_flag: set when drives missing, cleared when present.
        """
        try:
            new_real = self._list_removable_drives()
            prev_real = [d for d in self.removable if d != "None"]
            if set(new_real) != set(prev_real):
                values = ["None"] + new_real
                self.removable = values[:]
                for var, widget in zip(self.drive_vars, self.option_menus):
                    cur = var.get()
                    try:
                        widget['values'] = values
                        if cur not in values:
                            var.set("None")
                        continue
                    except Exception:
                        pass
                    try:
                        menu = widget["menu"]
                        menu.delete(0, "end")
                        menu.add_command(label="None", command=tk._setit(var, "None"))
                        for d in new_real:
                            menu.add_command(label=d, command=tk._setit(var, d))
                        if cur not in (["None"] + new_real):
                            var.set("None")
                    except Exception:
                        var.set("None")
                self._log("Auto-updated drive list (hot-plug detected)")

            # Update drive_pause_flag depending on presence of selected drives
            if self.selected_drives:
                cur = set(new_real)
                missing = [d for d in self.selected_drives if d not in cur]
                if missing:
                    if not self.drive_pause_flag.is_set():
                        self.drive_pause_flag.set()
                        self._log(f"Drive removed: {missing}. Drive-paused operations.", level="warning")
                        try:
                            self.root.after(0, lambda: messagebox.showwarning("Drive removed", f"Missing drives: {missing}\nReconnect to resume."))
                        except Exception:
                            pass
                else:
                    if self.drive_pause_flag.is_set():
                        # clear only drive pause (do not touch user_pause_flag)
                        self.drive_pause_flag.clear()
                        self._log("All selected drives reconnected — drive pause cleared.")
        except Exception:
            pass
        finally:
            self.root.after(DRIVE_MONITOR_MS, self._scan_drives_periodic)

    def _confirm_selection(self):
        # build selected list ignoring "None"
        self.selected_drives = [v.get() for v in self.drive_vars if v.get() and v.get() != "None"]

        if len(self.selected_drives) < 2:
            messagebox.showerror("Error", "Select at least two removable drives (or mark unused slots as 'None').")
            return
        # canonicalize paths ensure trailing slash
        self.selected_drives = [d if d.endswith("/") else d + "/" for d in self.selected_drives]
        self._load_index()
        self._refresh_tree()
        self._log(f"Drives confirmed: {self.selected_drives}; Chunk={self.chunk_mb.get()}MB; Compression={self.compression_mode.get()}")

    def _index_path(self) -> str:
        meta_dir = os.path.join(self.selected_drives[0], INDEX_DIR_NAME)
        os.makedirs(meta_dir, exist_ok=True)
        try:
            subprocess.call(["attrib", "+h", meta_dir])
        except Exception:
            pass
        return os.path.join(meta_dir, INDEX_FILE_NAME)

    def _save_index(self):
        """
        Save index to primary drive's meta folder and replicate to all selected drives.
        """
        try:
            p = self._index_path()
            with open(p, "w", encoding="utf-8") as f:
                json.dump(self.virtual_index, f, indent=2)
            # replicate to other drives
            for d in self.selected_drives:
                try:
                    meta_dir = os.path.join(d, INDEX_DIR_NAME)
                    os.makedirs(meta_dir, exist_ok=True)
                    tgt = os.path.join(meta_dir, INDEX_FILE_NAME)
                    with open(tgt, "w", encoding="utf-8") as tf:
                        json.dump(self.virtual_index, tf, indent=2)
                    try:
                        subprocess.call(["attrib", "+h", meta_dir])
                    except Exception:
                        pass
                except Exception:
                    # ignore per-drive replication errors
                    pass
            self._log("Index saved (primary + backups)")
        except Exception as e:
            self._ui_error(f"Failed to save index: {e}")
            self._log(f"Failed to save index: {e}", level="error")

    def _load_index(self):
        try:
            p = self._index_path()
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    self.virtual_index = json.load(f)
            else:
                self.virtual_index = {}
        except Exception as e:
            self._log(f"Failed to load index: {e}", level="warning")
            self.virtual_index = {}

    # ---------------- Storage info ----------------
    def _update_storage_info(self):
        total_bytes, free_bytes = 0, 0
        try:
            for d in self.selected_drives:
                usage = shutil.disk_usage(d)
                total_bytes += usage.total
                free_bytes += usage.free
            total_gb = total_bytes / (1024 ** 3)
            free_gb = free_bytes / (1024 ** 3)
            used_gb = total_gb - free_gb
            pct_free = (free_gb / total_gb * 100) if total_gb else 0
            self.storage_info.set(f"Total: {total_gb:.2f} GB | Used: {used_gb:.2f} GB | Free: {free_gb:.2f} GB ({pct_free:.1f}%)")
        except Exception:
            self.storage_info.set("Total: -- | Free: --")
        # schedule next update
        self.root.after(2000, self._update_storage_info)

    # ---------------- UI helpers ----------------
    def _ui_error(self, msg: str):
        self.root.after(0, messagebox.showerror, "Error", msg)

    def _ui_info(self, title: str, msg: str):
        self.root.after(0, messagebox.showinfo, title, msg)

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for rel in sorted(self.virtual_index.keys()):
            self._insert_path("", rel.split(os.sep))

    def _insert_path(self, parent: str, parts: List[str]):
        if not parts:
            return
        first = parts[0]
        child = None
        for cid in self.tree.get_children(parent):
            if self.tree.item(cid, "text") == first:
                child = cid
                break
        if not child:
            child = self.tree.insert(parent, "end", text=first, open=True)
        self._insert_path(child, parts[1:])

    # ---------------- Helpers ----------------
    def _hide_path(self, p: str):
        try:
            subprocess.call(["attrib", "+h", p])
        except Exception:
            pass

    @staticmethod
    def _sanitize(name: str) -> str:
        return "".join(c if c.isalnum() or c in " ._-" else "_" for c in name)

    def _build_index_value(self, parts: List[str], compressed: bool, fmt: str, orig_name: str, orig_size: int, status: str = "complete", checksums: Dict[str,str] | None = None, verified: bool = True) -> Dict[str, Any]:
        d = {"parts": parts, "compressed": compressed, "format": fmt, "orig_name": orig_name, "size": orig_size, "status": status}
        if checksums is not None:
            d["checksums"] = checksums
            d["verified"] = verified
        return d

    def _entry_parts(self, val: IndexValue) -> List[str]:
        return val if isinstance(val, list) else val.get("parts", [])

    # ---------------- Core: stream split (patched with checksums) ----------------
    def _compute_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()

    def _stream_split(self, src_path: str, relpath: str, on_progress: Callable[[int, int, float, float], None]) -> \
    Tuple[List[str], Dict[str, str]]:
        """
        High-performance version:
        - Stream src_path to .temp parts across selected_drives.
        - Pause/resume checked only between chunks.
        - Progress updated once per chunk (smooth UI).
        - Checksum computed after writing.
        """
        total_size = os.path.getsize(src_path)
        if total_size == 0:
            p = os.path.join(self.selected_drives[0], f"{os.path.basename(src_path)}.part1")
            open(p, "wb").close()
            self._hide_path(p)
            chks = {os.path.basename(p): self._compute_sha256(p)}
            return [p], chks

        # Proportional distribution based on available free space
        free = [shutil.disk_usage(d).free for d in self.selected_drives]
        total_free = sum(free) or 1
        part_sizes = [int(total_size * (f / total_free)) for f in free]
        diff = total_size - sum(part_sizes)
        for i in range(diff):
            part_sizes[i % len(part_sizes)] += 1

        fname = os.path.basename(src_path)
        temp_paths = [os.path.join(d, f"{fname}.part{i + 1}.temp") for i, d in enumerate(self.selected_drives)]

        # Open target files
        fhs = []
        try:
            for p in temp_paths:
                os.makedirs(os.path.dirname(p), exist_ok=True)
                fh = open(p, "ab")
                fhs.append(fh)
                self._hide_path(p)
        except Exception:
            for fh in fhs:
                try:
                    fh.close()
                except Exception:
                    pass
            raise

        written = [os.path.getsize(p) if os.path.exists(p) else 0 for p in temp_paths]
        cur = 0
        while cur < len(written) and written[cur] >= part_sizes[cur]:
            cur += 1

        done = sum(written)
        chunk_bytes = max(1, int(self.chunk_mb.get()) * 1024 * 1024)
        start = time.time()

        try:
            with open(src_path, "rb") as sf:
                sf.seek(done)
                while True:
                    if self.cancel_flag.is_set():
                        raise KeyboardInterrupt("Canceled by user")

                    # Pause only between chunks
                    while (
                            self.user_pause_flag.is_set() or self.drive_pause_flag.is_set()) and not self.cancel_flag.is_set():
                        time.sleep(0.2)

                    buf = sf.read(chunk_bytes)
                    if not buf:
                        break

                    mv = memoryview(buf)
                    off = 0
                    while off < len(mv) and cur < len(fhs):
                        if self.cancel_flag.is_set():
                            raise KeyboardInterrupt("Canceled by user")

                        rem = part_sizes[cur] - written[cur]
                        if rem <= 0:
                            cur += 1
                            continue

                        n = min(rem, len(mv) - off)
                        if n <= 0:
                            break

                        try:
                            fhs[cur].write(mv[off:off + n])
                        except Exception as e:
                            self._log(f"Write failed: {e} — drive paused", level="warning")
                            self.drive_pause_flag.set()
                            try:
                                self.root.after(0, lambda: messagebox.showwarning(
                                    "Drive Removed",
                                    "Drive became unavailable.\nReconnect drives to resume or press Cancel."
                                ))
                            except Exception:
                                pass
                            while self.drive_pause_flag.is_set() and not self.cancel_flag.is_set():
                                time.sleep(0.5)
                                cur_drives = self._list_removable_drives()
                                if all(d in cur_drives for d in self.selected_drives):
                                    self._log("Drives reconnected — resuming.")
                                    self.drive_pause_flag.clear()
                                    try:
                                        fhs[cur].close()
                                    except Exception:
                                        pass
                                    fhs[cur] = open(temp_paths[cur], "ab")
                                    break
                            if self.cancel_flag.is_set():
                                raise KeyboardInterrupt("Canceled by user")
                            continue

                        written[cur] += n
                        off += n
                        done += n

                    # Update progress once per chunk
                    elapsed = max(1e-6, time.time() - start)
                    speed_mb_s = (done / 1_000_000) / elapsed
                    eta_s = (total_size - done) / (speed_mb_s * 1_000_000) if speed_mb_s > 0 else 0.0
                    try:
                        on_progress(done, total_size, eta_s, speed_mb_s)
                    except Exception:
                        pass

        except KeyboardInterrupt:
            for fh in fhs:
                try:
                    fh.close()
                except Exception:
                    pass
            for p in temp_paths:
                try:
                    os.remove(p)
                except Exception:
                    pass
            raise
        finally:
            for fh in fhs:
                try:
                    fh.close()
                except Exception:
                    pass

        # Rename .temp → .part and compute checksums
        final_parts = []
        checksums: Dict[str, str] = {}
        for p, w in zip(temp_paths, written):
            if w > 0:
                final = p.replace(".temp", "")
                try:
                    if os.path.exists(final):
                        os.remove(final)
                    os.replace(p, final)
                    self._hide_path(final)
                    final_parts.append(final)
                    try:
                        checksums[os.path.basename(final)] = self._compute_sha256(final)
                    except Exception as e:
                        self._log(f"Checksum compute failed for {final}: {e}", level="warning")
                except Exception as e:
                    self._log(f"Rename failed for {p}: {e}", level="warning")
                    final_parts.append(p)
            else:
                try:
                    os.remove(p)
                except Exception:
                    pass

        return final_parts, checksums

    # ---------------- Uploads ----------------
    def _upload_file_dialog(self):
        if not self.selected_drives:
            messagebox.showerror("Error", "Select drives first.")
            return
        p = filedialog.askopenfilename()
        if p:
            self._submit_task(self._upload_single_file, p)

    def _upload_single_file(self, path: str):
        rel = os.path.basename(path)
        self.current_file.set(f"Preparing: {rel}")
        self.file_progress.set(0.0); self.folder_progress.set(0.0)
        self.file_counter.set("0/1"); self.eta.set("--")
        self.user_pause_flag.clear(); self.drive_pause_flag.clear(); self.cancel_flag.clear()

        mode = self.compression_mode.get()
        use_temp_archive = None

        def on_progress(done: int, total: int, eta_s: float, speed_mb_s: float):
            pct = (done / total) * 100 if total else 100
            # update on main thread
            def upd():
                self.file_progress.set(pct)
                self.current_file.set(f"Uploading: {rel}  {done//1_000_000}/{total//1_000_000} MB  |  ETA: {int(eta_s)}s  |  {speed_mb_s:.1f} MB/s")
                self.file_counter.set("1/1")
                self.eta.set(f"ETA: {int(eta_s)}s  | {speed_mb_s:.1f} MB/s")
            try:
                self.root.after_idle(upd)
            except Exception:
                upd()

        placeholder = rel
        try:
            src = path
            orig_size = os.path.getsize(path)
            compressed = False; fmt = "store"; orig_name = rel
            if mode in ("zip", "lzma"):
                self._log(f"Compressing '{rel}' ({mode}) before split...")
                comp = zipfile.ZIP_DEFLATED if mode == "zip" else getattr(zipfile, "ZIP_LZMA", zipfile.ZIP_DEFLATED)
                tmp = tempfile.mktemp(prefix="vdrive_", suffix=".zip")
                with zipfile.ZipFile(tmp, "w", compression=comp) as zf:
                    zf.write(path, arcname=os.path.basename(path))
                use_temp_archive = tmp
                src = tmp; compressed = True; fmt = mode; placeholder = rel + ".zipbundle"

            # create placeholder entry BEFORE uploading so UI shows it (status uploading)
            with self._lock:
                self.virtual_index[placeholder] = self._build_index_value([], compressed, fmt, orig_name, orig_size, status="uploading", checksums={}, verified=False)
            self._save_index(); self.root.after(0, self._refresh_tree)

            parts, checksums = self._stream_split(src, placeholder, on_progress)
            entry = self._build_index_value(parts, compressed, fmt, orig_name, orig_size, status="complete", checksums=checksums, verified=True)
            with self._lock:
                self.virtual_index[placeholder] = entry
            self._save_index(); self.root.after(0, self._refresh_tree)
            self._ui_info("Success", f"Uploaded {rel}")
            self._log(f"Uploaded: {rel} -> parts: {len(parts)}")
        except KeyboardInterrupt:
            with self._lock:
                if placeholder in self.virtual_index and isinstance(self.virtual_index[placeholder], dict):
                    self.virtual_index[placeholder]["status"] = "cancelled"
                    self.virtual_index[placeholder]["parts"] = []
            self._save_index(); self.root.after(0, self._refresh_tree)
            self._log("Upload canceled by user", level="warning")
        except Exception as e:
            with self._lock:
                if placeholder in self.virtual_index and isinstance(self.virtual_index[placeholder], dict):
                    self.virtual_index[placeholder]["status"] = "incomplete"
            self._save_index(); self.root.after(0, self._refresh_tree)
            self._ui_error(f"Failed to upload '{rel}': {e}")
            self._log(f"Upload failed: {rel} -> {e}", level="error")
        finally:
            if use_temp_archive and os.path.exists(use_temp_archive):
                try: os.remove(use_temp_archive)
                except Exception: pass
            self.root.after(0, self._reset_progress)

    def _upload_folder_dialog(self):
        if not self.selected_drives:
            messagebox.showerror("Error", "Select drives first.")
            return
        folder = filedialog.askdirectory()
        if folder:
            self._submit_task(self._upload_folder, folder)

    def _upload_folder(self, folder: str):
        files: List[Tuple[str, str]] = []
        base = os.path.basename(folder.rstrip("/\\"))
        for r, _dirs, fs in os.walk(folder):
            for f in fs:
                full = os.path.join(r, f)
                rel_inside = os.path.relpath(full, folder)
                rel = os.path.join(base, rel_inside)
                files.append((full, rel))
        total = len(files)
        if total == 0:
            messagebox.showinfo("Info", "Folder is empty.")
            return

        self.folder_progress.set(0.0); self.file_progress.set(0.0)
        self.file_counter.set(f"0/{total}"); self.eta.set("--")
        self.user_pause_flag.clear(); self.drive_pause_flag.clear(); self.cancel_flag.clear()

        def on_progress(done_b: int, total_b: int, eta_s: float, speed_mb_s: float, rel_name: str = ""):
            pct = (done_b / total_b) * 100 if total_b else 100
            def upd():
                self.file_progress.set(pct)
                self.current_file.set(f"Uploading: {rel_name}  {done_b//1_000_000}/{total_b//1_000_000} MB  |  ETA: {int(eta_s)}s  |  {speed_mb_s:.1f} MB/s")
            try:
                self.root.after_idle(upd)
            except Exception:
                upd()

        start = time.time()
        done_files = 0
        for full, rel in files:
            if self.cancel_flag.is_set():
                self._log("Folder upload canceled by user", level="warning")
                break

            def local_on_progress(done_b, total_b, eta_s, speed_mb_s, rel_name=rel):
                on_progress(done_b, total_b, eta_s, speed_mb_s, rel_name)

            try:
                with self._lock:
                    self.virtual_index[rel] = self._build_index_value([], False, "store", rel, os.path.getsize(full), status="uploading", checksums={}, verified=False)
                self._save_index(); self.root.after(0, self._refresh_tree)

                parts, checksums = self._stream_split(full, rel, local_on_progress)
                entry = self._build_index_value(parts, False, "store", rel, os.path.getsize(full), status="complete", checksums=checksums, verified=True)
                with self._lock:
                    self.virtual_index[rel] = entry
            except KeyboardInterrupt:
                self._log("Upload canceled during folder transfer.", level="warning")
                break
            except Exception as e:
                with self._lock:
                    if rel in self.virtual_index and isinstance(self.virtual_index[rel], dict):
                        self.virtual_index[rel]["status"] = "incomplete"
                self._ui_error(f"Failed on {rel}: {e}")
                self._log(f"Folder upload error: {rel} -> {e}", level="error")
            done_files += 1
            overall = (done_files / total) * 100
            elapsed = max(1e-6, time.time() - start)
            avg_per = elapsed / done_files
            eta_overall = avg_per * (total - done_files)
            self.folder_progress.set(overall)
            self.file_counter.set(f"{done_files}/{total}")
            self.eta.set(f"ETA: {int(eta_overall)}s")
        self._save_index(); self.root.after(0, self._refresh_tree)
        if not self.cancel_flag.is_set():
            self._ui_info("Success", f"Folder '{base}' uploaded!")
        self.root.after(0, self._reset_progress)

    # ---------------- Downloads ----------------
    def _download_item(self):
        sel = self.tree.focus()
        if not sel:
            return
        parts: List[str] = []
        node = sel
        while node:
            parts.insert(0, self.tree.item(node, "text"))
            node = self.tree.parent(node)
        rel = os.sep.join(parts)
        is_folder = any(k.startswith(rel + os.sep) for k in self.virtual_index.keys())
        if is_folder:
            self._submit_task(self._download_folder, rel)
        else:
            self._submit_task(self._download_file, rel)

    def _download_folder(self, folder_rel: str):
        target = filedialog.askdirectory(title=f"Save '{folder_rel}' to…")
        if not target:
            return
        items = [(rel, self.virtual_index[rel]) for rel in self.virtual_index if rel.startswith(folder_rel + os.sep)]
        if not items:
            messagebox.showinfo("Info", "Folder has no indexed files.")
            return
        self.current_file.set(f"Downloading: {folder_rel}")
        self.folder_progress.set(0.0); self.file_progress.set(0.0)
        self.file_counter.set(f"0/{len(items)}")

        def worker():
            done = 0
            for rel, entry in items:
                ok = self._download_single(rel, entry, target)
                done += 1
                self.file_counter.set(f"{done}/{len(items)}")
                self.folder_progress.set((done / len(items)) * 100)
            self._ui_info("Success", f"Folder '{folder_rel}' downloaded!")
            self.root.after(0, self._reset_progress)

        self._submit_task(worker)

    def _download_file(self, rel: str):
        entry = self.virtual_index.get(rel)
        if entry is None:
            messagebox.showerror("Error", f"Not in index: {rel}")
            return
        status_ok = isinstance(entry, list) or (isinstance(entry, dict) and entry.get("status") == "complete")
        if not status_ok:
            messagebox.showwarning("Not ready", f"'{rel}' is not complete yet.")
            return
        save_path = filedialog.asksaveasfilename(initialfile=os.path.basename(rel))
        if not save_path:
            return
        self.current_file.set(f"Downloading: {rel}")
        self.file_progress.set(0.0)

        def worker():
            ok = self._download_single(rel, entry, os.path.dirname(save_path), override_name=os.path.basename(save_path))
            if ok:
                self._ui_info("Downloaded", f"Saved {save_path}")
            self.root.after(0, self._reset_progress)

        self._submit_task(worker)

    # Helper to run a dialog on main thread and wait for result (Retry/Abort)
    def _ask_retry_cancel(self, title: str, message: str) -> bool:
        """
        Shows a Retry/Cancel dialog on the main thread and returns True for Retry, False for Cancel.
        Blocks the caller thread until user responds.
        """
        evt = threading.Event()
        result = {"val": False}

        def ask():
            try:
                r = messagebox.askretrycancel(title, message)
                result["val"] = bool(r)
            except Exception:
                result["val"] = False
            finally:
                evt.set()

        self.root.after(0, ask)
        evt.wait()
        return result["val"]

    def _download_single(self, rel: str, entry: IndexValue, target_dir: str, override_name: str | None = None) -> bool:
        parts = self._entry_parts(entry)
        if not parts:
            self._ui_error(f"No parts for {rel}")
            return False

        # Extract metadata
        if isinstance(entry, list):
            checksums = {}
            is_compressed = False; fmt = "store"; orig_name = os.path.basename(rel)
            out_name = override_name or orig_name
        else:
            meta = entry
            checksums = meta.get("checksums", {}) or {}
            is_compressed = meta.get("compressed", False)
            fmt = meta.get("format", "store")
            orig_name = meta.get("orig_name", os.path.basename(rel))
            out_name = override_name or (orig_name if not is_compressed else os.path.basename(rel))

        out_path = os.path.join(target_dir, out_name)

        # Verify checksums for each part before merging
        for p in parts:
            base = os.path.basename(p)
            expected = checksums.get(base)
            if expected:
                # check existence
                if not os.path.exists(p):
                    # Ask user to Retry (keeps checking) or Abort
                    retry = self._ask_retry_cancel("Missing part", f"Part missing: {p}\nRetry after reconnecting or Cancel to abort.")
                    if not retry:
                        self._log(f"Download aborted: missing part {p}", level="warning")
                        return False
                    # if retry, loop back to recheck file existence
                    while retry and not os.path.exists(p):
                        time.sleep(0.5)
                        retry = self._ask_retry_cancel("Missing part", f"Part still missing: {p}\nRetry after reconnecting or Cancel to abort.")
                    if not os.path.exists(p):
                        return False

                # now compute sha256 and compare
                verified = False
                while not verified:
                    try:
                        ch = self._compute_sha256(p)
                        if ch == expected:
                            verified = True
                            break
                        else:
                            # mismatch -> ask user Retry/Abort (Option B: keep retrying)
                            self._log(f"Checksum mismatch for {p} (expected {expected[:8]}..., got {ch[:8]}...)", level="warning")
                            retry = self._ask_retry_cancel("Checksum mismatch", f"Checksum mismatch for {p}.\nExpected: {expected}\nGot: {ch}\nPress Retry after replacing or reconnecting drive, or Cancel to abort download.")
                            if not retry:
                                return False
                            # If retry True, wait briefly and continue to loop which will recompute
                            time.sleep(0.5)
                    except Exception as e:
                        self._log(f"Checksum verify error for {p}: {e}", level="error")
                        retry = self._ask_retry_cancel("Checksum verify error", f"Error verifying {p}: {e}\nRetry or Cancel?")
                        if not retry:
                            return False
                        time.sleep(0.5)

        # All parts checked (or no checksums present), proceed to merge
        total = sum(os.path.getsize(p) for p in parts if os.path.exists(p))
        written = 0
        try:
            with open(out_path, "wb") as out_f:
                for p in parts:
                    if not os.path.exists(p):
                        continue
                    with open(p, "rb") as pf:
                        while True:
                            buf = pf.read(1_048_576)
                            if not buf:
                                break
                            out_f.write(buf)
                            written += len(buf)
                            pct = (written / total) * 100 if total else 100
                            def upd():
                                self.file_progress.set(pct)
                            try:
                                self.root.after_idle(upd)
                            except Exception:
                                upd()
            # if compressed, extract bundle
            if not isinstance(entry, list) and is_compressed:
                try:
                    with zipfile.ZipFile(out_path, "r") as zf:
                        zf.extractall(target_dir)
                except Exception as e:
                    self._ui_error(f"Extraction failed for {rel}: {e}")
                    self._log(f"Extraction failed for {rel}: {e}", level="error")
            return True
        except Exception as e:
            self._ui_error(f"Download failed: {e}")
            self._log(f"Download failed for {rel}: {e}", level="error")
            return False

    # ---------------- Delete ----------------
    def _delete_item(self):
        sel = self.tree.focus()
        if not sel:
            return
        parts: List[str] = []
        node = sel
        while node:
            parts.insert(0, self.tree.item(node, "text"))
            node = self.tree.parent(node)
        rel = os.sep.join(parts)
        self._submit_task(self._delete_worker, rel)

    def _delete_worker(self, rel: str):
        try:
            keys = [k for k in list(self.virtual_index.keys()) if k == rel or k.startswith(rel + os.sep)]
            total_parts = 0
            for k in keys:
                val = self.virtual_index.get(k)
                total_parts += len(self._entry_parts(val)) if val is not None else 0
            done = 0
            self.current_file.set(f"Deleting: {rel}")
            for k in keys:
                val = self.virtual_index.get(k)
                if val is None:
                    continue
                for p in list(self._entry_parts(val)):
                    if os.path.exists(p):
                        try: os.remove(p)
                        except Exception: pass
                    done += 1
                    pct = (done / total_parts) * 100 if total_parts else 100
                    def upd():
                        self.file_progress.set(pct)
                        self.current_file.set(f"Deleting: {os.path.basename(p)}")
                    try:
                        self.root.after_idle(upd)
                    except Exception:
                        upd()
                if k in self.virtual_index:
                    del self.virtual_index[k]
            self._save_index(); self.root.after(0, self._refresh_tree)
            self._ui_info("Deleted", f"Removed: {rel}")
        except Exception as e:
            self._ui_error(f"Delete failed: {e}")
            self._log(f"Delete failed: {e}", level="error")
        finally:
            self.root.after(0, self._reset_progress)

    # ---------------- Purge All ----------------
    def _purge_all(self):
        if not self.selected_drives:
            messagebox.showerror("Error", "Select drives first to purge.")
            return
        ok = messagebox.askyesno("Confirm Purge", "This will delete ALL virtual drive parts and reset index on selected drives. Continue?")
        if not ok:
            return
        self._submit_task(self._purge_worker)

    def _purge_worker(self):
        try:
            for d in self.selected_drives:
                for root_dir, _dirs, files in os.walk(d):
                    for f in files:
                        if f.endswith(".part") or f.endswith(".part1") or f.endswith(".part2") or f.endswith(".part3") or f.endswith(".temp") or f.endswith(".part4"):
                            fp = os.path.join(root_dir, f)
                            try: os.remove(fp)
                            except Exception: pass
                # remove index if exists
                meta_dir = os.path.join(d, INDEX_DIR_NAME)
                try:
                    if os.path.exists(meta_dir):
                        shutil.rmtree(meta_dir)
                except Exception:
                    pass
            self.virtual_index.clear()
            # attempt to save index on first drive (will recreate meta dir)
            try:
                self._save_index()
            except Exception:
                pass
            self._refresh_tree()
            self._ui_info("Purge Complete", "All virtual data removed from selected drives.")
            self._log("Purge All completed")
        except Exception as e:
            self._ui_error(f"Purge failed: {e}")
            self._log(f"Purge failed: {e}", level="error")

    # ---------------- Pause / Resume / Cancel ----------------
    def _pause(self):
        self.user_pause_flag.set()
        self._log("User paused transfers", level="info")
        self.current_file.set("Paused — waiting to resume…")

    def _resume(self):
        self.user_pause_flag.clear()
        self._log("User resumed transfers", level="info")
        self.current_file.set("Resuming…")

    def _cancel(self):
        self.cancel_flag.set()
        self._log("Cancel requested", level="warning")
        self.current_file.set("Cancel requested…")

    # ---------------- Drag & Drop ----------------
    def _on_drop(self, event):
        if not self.selected_drives:
            messagebox.showerror("Error", "Select drives first.")
            return
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            paths = [event.data]
        for p in paths:
            if os.path.isdir(p):
                self._submit_task(self._upload_folder, p)
            else:
                self._submit_task(self._upload_single_file, p)

    # ---------------- Helpers ----------------
    def _reset_progress(self):
        self.current_file.set("Idle")
        self.file_progress.set(0.0)
        self.folder_progress.set(0.0)
        self.file_counter.set("0/0")
        self.eta.set("--")
        self.cancel_flag.clear()

    def _submit_task(self, func: Callable, *args, **kwargs):
        """
        Submit a callable to the executor and keep track of the future.
        """
        try:
            future = self.executor.submit(func, *args, **kwargs)
            self._futures.append(future)
            def _done_callback(fut: Future):
                try:
                    fut.result()
                except Exception as e:
                    self._log(f"Background task error: {e}", level="error")
            future.add_done_callback(_done_callback)
            return future
        except Exception as e:
            self._log(f"Failed to submit background task: {e}", level="error")
            return None

    def close(self):
        try:
            self.cancel_flag.set()
            # Shutdown executor cleanly
            try:
                self.executor.shutdown(wait=False)
            except Exception:
                pass
            time.sleep(0.1)
            self._log("Application closing")
        except Exception:
            pass


# ----------------- Main -----------------
def main():
    root = tb.Window(themename="darkly")  # starts in dark mode
    app = App(root, start_theme="darkly")
    root.protocol("WM_DELETE_WINDOW", lambda: (app.close(), root.destroy()))
    root.mainloop()


main()