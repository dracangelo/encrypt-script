#!/usr/bin/env python3
"""
encrypt_files_gui.py — AES-256 File Encryption Tool with GUI
Enhanced with: Key-file support, Auto-lock (5 min inactivity), Drag & drop, 
Folder recursion, .enc preview, System tray, Dark/Light theme toggle
Run: python encrypt_files_gui.py
"""

import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

# ─── Extra dependencies (auto-install) ───────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "--break-system-packages"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend

try:
    from tkinterdnd2 import *
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tkinterdnd2", "--break-system-packages"])
    from tkinterdnd2 import *

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pystray", "pillow", "--break-system-packages"])
    import pystray
    from PIL import Image, ImageDraw

SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 600_000
ENC_SUFFIX = ".enc"
CHUNK_SIZE = 64 * 1024


def derive_key(password: str, salt: bytes, keyfile_path: str = "") -> bytes:
    keyfile_bytes = b""
    if keyfile_path:
        try:
            with open(keyfile_path, "rb") as f:
                keyfile_bytes = f.read(1 << 20)  # max 1 MiB
        except Exception as e:
            raise ValueError(f"Failed to read key file: {e}")
    data = password.encode("utf-8") + keyfile_bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(data)


def encrypt_file(filepath: str, password: str, keyfile_path: str = "") -> str:
    src = Path(filepath)
    dst = Path(str(src) + ENC_SUFFIX)
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt, keyfile_path)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(salt)
        fout.write(iv)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(encryptor.update(padder.update(chunk)))
        fout.write(encryptor.update(padder.finalize()))
        fout.write(encryptor.finalize())
    return str(dst)


def decrypt_file(filepath: str, password: str, keyfile_path: str = "") -> str:
    src = Path(filepath)
    dst = Path(filepath[: -len(ENC_SUFFIX)])
    with open(src, "rb") as fin:
        salt = fin.read(SALT_SIZE)
        iv = fin.read(IV_SIZE)
        key = derive_key(password, salt, keyfile_path)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        with open(dst, "wb") as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(unpadder.update(decryptor.update(chunk)))
            try:
                fout.write(unpadder.update(decryptor.finalize()))
                fout.write(unpadder.finalize())
            except Exception:
                dst.unlink(missing_ok=True)
                raise ValueError("Wrong password, key file, or corrupted file.")
    return str(dst)


# ─── GUI ──────────────────────────────────────────────────────────────────────

FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI Semibold", 11)


class EncryptApp(Tk):
    def __init__(self):
        super().__init__()
        self.title("FileVault — AES-256 Encryption")
        self.geometry("820x660")
        self.minsize(720, 560)
        self.configure(bg="#0d0f14")

        self.files: list[str] = []
        self.mode = tk.StringVar(value="encrypt")
        self.keyfile_var = tk.StringVar()
        self.pw_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.show_pw = tk.BooleanVar(value=False)
        self.delete_orig = tk.BooleanVar(value=False)
        self.tray_enabled = tk.BooleanVar(value=False)
        self.is_dark = tk.BooleanVar(value=True)

        self.tray_icon = None
        self.last_activity = time.time()
        self.inactivity_timeout = 300  # seconds

        self.section_labels: list[tk.Widget] = []
        self.mode_radios: list[tk.Widget] = []

        self._init_colors()
        self._build_ui()

        # Drag & drop
        self.drop_target_register(DND_FILES)
        self.dnd_bind("<<Drop>>", self._on_drop)

        # Activity / auto-lock
        self.bind_all("<KeyPress>", self._reset_activity)
        self.bind_all("<Button>", self._reset_activity)
        self.bind_all("<Motion>", self._reset_activity)
        self.after(30000, self._check_inactivity)

        # Close handling
        self.protocol("WM_DELETE_WINDOW", self._handle_close)

        self.mode.trace_add("write", self._on_mode_change)

    def _init_colors(self):
        self.dark_colors = {
            "BG": "#0d0f14", "PANEL": "#161920", "BORDER": "#252a35",
            "ACCENT": "#00e5ff", "ACCENT2": "#7c3aed",
            "ACCENT_ACTIVE": "#00b8cc", "ACCENT2_ACTIVE": "#6d28d9",
            "TEXT": "#e8eaf0", "MUTED": "#6b7280",
            "SUCCESS": "#22c55e", "ERROR": "#ef4444", "WARNING": "#f59e0b",
        }
        self.light_colors = {
            "BG": "#f8fafc", "PANEL": "#ffffff", "BORDER": "#cbd5e1",
            "ACCENT": "#0ea5e9", "ACCENT2": "#8b5cf6",
            "ACCENT_ACTIVE": "#0284c8", "ACCENT2_ACTIVE": "#6f42c1",
            "TEXT": "#0f172a", "MUTED": "#64748b",
            "SUCCESS": "#16a34a", "ERROR": "#ef4444", "WARNING": "#ea580c",
        }
        self.colors = self.dark_colors.copy()

    # ── layout ────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        self.header = tk.Frame(self, bg=self.colors["PANEL"], height=56)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)

        self.title_label = tk.Label(
            self.header, text="🔐  FileVault", font=FONT_HEAD,
            fg=self.colors["ACCENT"], bg=self.colors["PANEL"], padx=20
        )
        self.title_label.pack(side="left", pady=12)

        self.subtitle_label = tk.Label(
            self.header, text="AES-256-CBC · PBKDF2-SHA256 · Keyfile + Folders + Tray",
            font=("Segoe UI", 9), fg=self.colors["MUTED"], bg=self.colors["PANEL"]
        )
        self.subtitle_label.pack(side="left", pady=14)

        self.theme_btn = tk.Button(
            self.header, text="🌙", font=("Segoe UI", 14), fg=self.colors["ACCENT"],
            bg=self.colors["PANEL"], bd=0, padx=12, cursor="hand2",
            command=self._toggle_theme
        )
        self.theme_btn.pack(side="right", padx=12)

        # Body
        self.body = tk.Frame(self, bg=self.colors["BG"])
        self.body.pack(fill="both", expand=True, padx=18, pady=14)

        # Left column
        self.left = tk.Frame(self.body, bg=self.colors["BG"])
        self.left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self._section(self.left, "MODE")
        mode_row = tk.Frame(self.left, bg=self.colors["BG"])
        mode_row.pack(fill="x", pady=(0, 12))
        for label, val in [("Encrypt files", "encrypt"), ("Decrypt .enc files", "decrypt")]:
            self._radio(mode_row, label, val)

        self._section(self.left, "FILES")
        btn_row = tk.Frame(self.left, bg=self.colors["BG"])
        btn_row.pack(fill="x", pady=(0, 6))

        self.add_files_btn = self._btn(btn_row, "＋ Add Files", self._add_files, self.colors["ACCENT"], "")
        self.add_files_btn.pack(side="left", padx=(0, 6))
        self.add_folder_btn = self._btn(btn_row, "📁 Add Folder", self._add_folder, self.colors["ACCENT"], "")
        self.add_folder_btn.pack(side="left", padx=(0, 6))
        self.preview_btn = self._btn(btn_row, "👁 Preview", self._preview_selected, self.colors["ACCENT"], "")
        self.preview_btn.pack(side="left", padx=(0, 6))
        self.remove_btn = self._btn(btn_row, "✕ Remove Selected", self._remove_selected, self.colors["ERROR"], "")
        self.remove_btn.pack(side="left", padx=(0, 6))
        self.clear_btn = self._btn(btn_row, "Clear All", self._clear_files, self.colors["MUTED"], "")
        self.clear_btn.pack(side="left")

        self.list_frame = tk.Frame(self.left, bg=self.colors["PANEL"], bd=0,
                                   highlightthickness=1, highlightbackground=self.colors["BORDER"])
        self.list_frame.pack(fill="both", expand=True, pady=(0, 4))

        scrollbar = tk.Scrollbar(self.list_frame, bg=self.colors["PANEL"],
                                 troughcolor=self.colors["PANEL"], activebackground=self.colors["ACCENT"],
                                 relief="flat", bd=0, width=10)
        scrollbar.pack(side="right", fill="y")

        self.file_list = tk.Listbox(
            self.list_frame, bg=self.colors["PANEL"], fg=self.colors["TEXT"],
            selectbackground=self.colors["ACCENT2"], selectforeground="white",
            font=FONT_MONO, bd=0, highlightthickness=0, activestyle="none",
            selectmode="extended", yscrollcommand=scrollbar.set
        )
        self.file_list.pack(fill="both", expand=True, padx=8, pady=6)
        scrollbar.config(command=self.file_list.yview)

        self.file_count = tk.Label(self.left, text="No files added", font=("Segoe UI", 9),
                                   fg=self.colors["MUTED"], bg=self.colors["BG"], anchor="w")
        self.file_count.pack(fill="x")

        # Right column
        self.right = tk.Frame(self.body, bg=self.colors["BG"], width=260)
        self.right.pack(side="right", fill="y")
        self.right.pack_propagate(False)

        self._section(self.right, "PASSWORD")

        tk.Label(self.right, text="Password", font=FONT_UI,
                 fg=self.colors["MUTED"], bg=self.colors["BG"], anchor="w").pack(fill="x")
        self.pw_entry = self._entry(self.right, self.pw_var, show="●")
        self.pw_entry.pack(fill="x", pady=(2, 10))

        self.confirm_label = tk.Label(self.right, text="Confirm Password", font=FONT_UI,
                                      fg=self.colors["MUTED"], bg=self.colors["BG"], anchor="w")
        self.confirm_label.pack(fill="x")
        self.confirm_entry = self._entry(self.right, self.confirm_var, show="●")
        self.confirm_entry.pack(fill="x", pady=(2, 4))

        self.show_check = tk.Checkbutton(
            self.right, text="Show passwords", variable=self.show_pw,
            command=self._toggle_show, font=("Segoe UI", 9),
            fg=self.colors["MUTED"], bg=self.colors["BG"],
            activebackground=self.colors["BG"], activeforeground=self.colors["TEXT"],
            selectcolor=self.colors["PANEL"], bd=0, highlightthickness=0
        )
        self.show_check.pack(anchor="w", pady=(0, 14))

        # Key file
        tk.Label(self.right, text="Key File (optional)", font=FONT_UI,
                 fg=self.colors["MUTED"], bg=self.colors["BG"], anchor="w").pack(fill="x", pady=(8, 2))
        kf_frame = tk.Frame(self.right, bg=self.colors["BG"])
        kf_frame.pack(fill="x")
        self.keyfile_entry = tk.Entry(
            kf_frame, textvariable=self.keyfile_var, font=FONT_MONO, state="readonly",
            bg=self.colors["PANEL"], fg=self.colors["TEXT"], relief="flat", bd=0,
            highlightthickness=1, highlightbackground=self.colors["BORDER"],
            highlightcolor=self.colors["ACCENT"]
        )
        self.keyfile_entry.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.select_kf_btn = self._btn(kf_frame, "Select", self._select_keyfile, self.colors["ACCENT"], "")
        self.select_kf_btn.pack(side="left", padx=(0, 4))
        self.clear_kf_btn = self._btn(kf_frame, "Clear", self._clear_keyfile, self.colors["MUTED"], "")
        self.clear_kf_btn.pack(side="left")

        self._section(self.right, "OPTIONS")
        self.delete_check = tk.Checkbutton(
            self.right, text="Delete originals after successful operation",
            variable=self.delete_orig, font=("Segoe UI", 9),
            fg=self.colors["TEXT"], bg=self.colors["BG"],
            activebackground=self.colors["BG"], activeforeground=self.colors["TEXT"],
            selectcolor=self.colors["PANEL"], bd=0, highlightthickness=0, justify="left", wraplength=220
        )
        self.delete_check.pack(anchor="w", pady=(0, 8))

        tk.Checkbutton(
            self.right, text="Enable system tray (minimize to background)",
            variable=self.tray_enabled, font=("Segoe UI", 9),
            fg=self.colors["TEXT"], bg=self.colors["BG"],
            activebackground=self.colors["BG"], activeforeground=self.colors["TEXT"],
            selectcolor=self.colors["PANEL"], bd=0, highlightthickness=0, justify="left", wraplength=220
        ).pack(anchor="w", pady=(0, 18))

        self.go_btn = tk.Button(
            self.right, text="🔒  ENCRYPT", font=("Segoe UI Semibold", 12),
            bg=self.colors["ACCENT"], fg="#000000", activebackground=self.colors["ACCENT_ACTIVE"],
            bd=0, padx=14, pady=10, cursor="hand2", command=self._run
        )
        self.go_btn.pack(fill="x", pady=(0, 4))

        # Log
        self.log_frame = tk.Frame(self, bg=self.colors["PANEL"], height=140)
        self.log_frame.pack(fill="x", padx=18, pady=(0, 14))
        self.log_frame.pack_propagate(False)

        log_head = tk.Frame(self.log_frame, bg=self.colors["PANEL"])
        log_head.pack(fill="x", padx=10, pady=(6, 2))
        self.log_head_label = tk.Label(log_head, text="LOG", font=("Segoe UI Semibold", 9),
                                       fg=self.colors["MUTED"], bg=self.colors["PANEL"])
        self.log_head_label.pack(side="left")
        tk.Button(log_head, text="Clear", font=("Segoe UI", 8), fg=self.colors["MUTED"],
                  bg=self.colors["PANEL"], activebackground=self.colors["PANEL"], bd=0,
                  cursor="hand2", command=self._clear_log).pack(side="right")

        self.log = tk.Text(
            self.log_frame, bg=self.colors["PANEL"], fg=self.colors["TEXT"], font=FONT_MONO,
            bd=0, highlightthickness=0, state="disabled", wrap="word"
        )
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.log.tag_config("ok", foreground=self.colors["SUCCESS"])
        self.log.tag_config("err", foreground=self.colors["ERROR"])
        self.log.tag_config("warn", foreground=self.colors["WARNING"])
        self.log.tag_config("info", foreground=self.colors["ACCENT"])

        # Progress
        self.progress = ttk.Progressbar(self, mode="determinate", maximum=100)
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TProgressbar", troughcolor=self.colors["PANEL"],
                        background=self.colors["ACCENT"])
        self.progress.pack(fill="x", padx=18, pady=(0, 10))

    def _section(self, parent, text):
        f = tk.Frame(parent, bg=self.colors["BG"])
        f.pack(fill="x", pady=(4, 4))
        lbl = tk.Label(f, text=text, font=("Segoe UI Semibold", 8),
                       fg=self.colors["ACCENT"], bg=self.colors["BG"])
        lbl.pack(side="left")
        tk.Frame(f, bg=self.colors["BORDER"], height=1).pack(side="left", fill="x", expand=True, padx=(6, 0), pady=6)
        self.section_labels.append(lbl)

    def _radio(self, parent, label, value):
        rb = tk.Radiobutton(
            parent, text=label, variable=self.mode, value=value,
            font=FONT_UI, fg=self.colors["TEXT"], bg=self.colors["BG"],
            activebackground=self.colors["BG"], activeforeground=self.colors["ACCENT"],
            selectcolor=self.colors["PANEL"], bd=0, highlightthickness=0
        )
        rb.pack(side="left", padx=(0, 16))
        self.mode_radios.append(rb)

    def _btn(self, parent, text, cmd, fg, _bg):
        return tk.Button(
            parent, text=text, command=cmd, font=("Segoe UI", 9),
            fg=fg, bg=self.colors["PANEL"], activebackground=self.colors["BORDER"],
            activeforeground=fg, relief="flat", bd=0, padx=10, pady=5, cursor="hand2"
        )

    def _entry(self, parent, var, show=None):
        return tk.Entry(
            parent, textvariable=var, font=FONT_MONO,
            bg=self.colors["PANEL"], fg=self.colors["TEXT"], insertbackground=self.colors["ACCENT"],
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=self.colors["BORDER"], highlightcolor=self.colors["ACCENT"],
            show=show
        )

    # ── helpers ───────────────────────────────────────────────────────────────
    def _collect_paths(self, input_paths):
        collected = []
        for p_str in input_paths:
            p = Path(p_str)
            if p.is_file():
                collected.append(str(p))
            elif p.is_dir():
                for root, _, files in os.walk(p):
                    for name in files:
                        collected.append(str(Path(root) / name))
        return collected

    def _add_paths(self, paths):
        m = self.mode.get()
        added = 0
        for f in paths:
            f = str(Path(f))
            if f not in self.files and \
               ((m == "encrypt" and not f.endswith(ENC_SUFFIX)) or
                (m == "decrypt" and f.endswith(ENC_SUFFIX))):
                self.files.append(f)
                self.file_list.insert("end", Path(f).name + f"  [{self._size(f)}]")
                added += 1
        if added:
            self._update_count()
            self._log(f"Added {added} file(s).", "info")

    def _add_files(self):
        m = self.mode.get()
        if m == "encrypt":
            types = [("All files", "*.*")]
            title = "Select files to encrypt"
        else:
            types = [("Encrypted files", f"*{ENC_SUFFIX}"), ("All files", "*.*")]
            title = "Select .enc files to decrypt"
        picked = filedialog.askopenfilenames(title=title, filetypes=types)
        if picked:
            self._add_paths(picked)

    def _add_folder(self):
        m = self.mode.get()
        title = f"Select folder to {'encrypt' if m == 'encrypt' else 'decrypt'}"
        dir_path = filedialog.askdirectory(title=title)
        if dir_path:
            collected = self._collect_paths([dir_path])
            self._add_paths(collected)

    def _on_drop(self, event):
        paths = self.tk.splitlist(event.data)
        collected = self._collect_paths(paths)
        self._add_paths(collected)

    def _remove_selected(self):
        selected = list(self.file_list.curselection())
        for i in reversed(selected):
            self.files.pop(i)
            self.file_list.delete(i)
        self._update_count()

    def _clear_files(self):
        self.files.clear()
        self.file_list.delete(0, "end")
        self._update_count()

    def _update_count(self):
        n = len(self.files)
        self.file_count.config(text=f"{n} file(s) selected" if n else "No files added")

    def _toggle_show(self):
        char = "" if self.show_pw.get() else "●"
        self.pw_entry.config(show=char)
        self.confirm_entry.config(show=char)

    def _size(self, path):
        try:
            b = os.path.getsize(path)
            for unit in ("B", "KB", "MB", "GB"):
                if b < 1024:
                    return f"{b:.0f} {unit}"
                b /= 1024
            return f"{b:.1f} TB"
        except Exception:
            return "?"

    def _log(self, msg, tag=""):
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _clear_log(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    # ── new features ──────────────────────────────────────────────────────────
    def _select_keyfile(self):
        kf = filedialog.askopenfilename(title="Select Key File (any binary/text file)")
        if kf:
            self.keyfile_var.set(kf)
            self._log(f"✅ Key file set: {Path(kf).name}", "info")

    def _clear_keyfile(self):
        self.keyfile_var.set("")
        self._log("Key file cleared.", "info")

    def _preview_selected(self):
        sel = self.file_list.curselection()
        if not sel:
            return
        filepath = self.files[sel[0]]
        if not filepath.endswith(ENC_SUFFIX):
            messagebox.showinfo("Preview", "Preview only works on .enc files.")
            return
        try:
            size = os.path.getsize(filepath)
            mtime = os.path.getmtime(filepath)
            orig_name = Path(filepath).name[:-len(ENC_SUFFIX)]
            ct_size = size - SALT_SIZE - IV_SIZE
            info = f"""🔍 Encrypted File Preview

Name          : {Path(filepath).name}
Original name : {orig_name}
Encrypted size: {self._size(filepath)}
Ciphertext    : {ct_size:,} bytes
Est. original : ~{ct_size:,} bytes
Algorithm     : AES-256-CBC + PBKDF2-SHA256 ({ITERATIONS:,} iterations)
Modified      : {time.ctime(mtime)}
Note          : Password + optional key file required to decrypt."""
            messagebox.showinfo("Preview", info)
            self._log(f"Previewed {Path(filepath).name}", "info")
        except Exception as e:
            self._log(f"Preview error: {e}", "err")

    def _reset_activity(self, event=None):
        self.last_activity = time.time()

    def _check_inactivity(self):
        if time.time() - self.last_activity > self.inactivity_timeout:
            self._auto_lock()
        self.after(30000, self._check_inactivity)

    def _auto_lock(self):
        cleared = False
        if self.pw_var.get():
            self.pw_var.set("")
            cleared = True
        if self.confirm_var.get():
            self.confirm_var.set("")
            cleared = True
        if self.keyfile_var.get():
            self.keyfile_var.set("")
            cleared = True
        if cleared:
            self._log("🔒 Auto-locked (passwords & keyfile cleared after inactivity)", "warn")

    def _toggle_theme(self):
        self.is_dark.set(not self.is_dark.get())
        self._apply_theme()

    def _apply_theme(self):
        if self.is_dark.get():
            self.colors = self.dark_colors.copy()
            self.theme_btn.config(text="🌙")
        else:
            self.colors = self.light_colors.copy()
            self.theme_btn.config(text="☀️")

        self.configure(bg=self.colors["BG"])
        self.header.configure(bg=self.colors["PANEL"])
        self.title_label.config(bg=self.colors["PANEL"], fg=self.colors["ACCENT"])
        self.subtitle_label.config(bg=self.colors["PANEL"], fg=self.colors["MUTED"])
        self.body.configure(bg=self.colors["BG"])
        self.left.configure(bg=self.colors["BG"])
        self.right.configure(bg=self.colors["BG"])
        self.list_frame.configure(bg=self.colors["PANEL"], highlightbackground=self.colors["BORDER"])
        self.file_list.configure(bg=self.colors["PANEL"], fg=self.colors["TEXT"],
                                 selectbackground=self.colors["ACCENT2"])
        self.file_count.configure(bg=self.colors["BG"], fg=self.colors["MUTED"])

        self.pw_entry.configure(bg=self.colors["PANEL"], fg=self.colors["TEXT"],
                                highlightbackground=self.colors["BORDER"],
                                highlightcolor=self.colors["ACCENT"])
        self.confirm_entry.configure(bg=self.colors["PANEL"], fg=self.colors["TEXT"],
                                     highlightbackground=self.colors["BORDER"],
                                     highlightcolor=self.colors["ACCENT"])
        self.keyfile_entry.configure(bg=self.colors["PANEL"], fg=self.colors["TEXT"],
                                     highlightbackground=self.colors["BORDER"],
                                     highlightcolor=self.colors["ACCENT"])

        self.show_check.configure(bg=self.colors["BG"], fg=self.colors["MUTED"],
                                  activebackground=self.colors["BG"], selectcolor=self.colors["PANEL"])
        self.delete_check.configure(bg=self.colors["BG"], fg=self.colors["TEXT"],
                                    activebackground=self.colors["BG"], selectcolor=self.colors["PANEL"])

        # Buttons
        self.add_files_btn.config(fg=self.colors["ACCENT"], bg=self.colors["PANEL"],
                                  activebackground=self.colors["BORDER"])
        self.add_folder_btn.config(fg=self.colors["ACCENT"], bg=self.colors["PANEL"],
                                   activebackground=self.colors["BORDER"])
        self.preview_btn.config(fg=self.colors["ACCENT"], bg=self.colors["PANEL"],
                                activebackground=self.colors["BORDER"])
        self.remove_btn.config(fg=self.colors["ERROR"], bg=self.colors["PANEL"],
                               activebackground=self.colors["BORDER"])
        self.clear_btn.config(fg=self.colors["MUTED"], bg=self.colors["PANEL"],
                              activebackground=self.colors["BORDER"])
        self.select_kf_btn.config(fg=self.colors["ACCENT"], bg=self.colors["PANEL"],
                                  activebackground=self.colors["BORDER"])
        self.clear_kf_btn.config(fg=self.colors["MUTED"], bg=self.colors["PANEL"],
                                 activebackground=self.colors["BORDER"])

        # Mode radios
        for rb in self.mode_radios:
            rb.config(fg=self.colors["TEXT"], bg=self.colors["BG"],
                      activebackground=self.colors["BG"], activeforeground=self.colors["ACCENT"],
                      selectcolor=self.colors["PANEL"])

        # Sections
        for lbl in self.section_labels:
            lbl.config(fg=self.colors["ACCENT"], bg=self.colors["BG"])

        # Log
        self.log_frame.config(bg=self.colors["PANEL"])
        self.log_head_label.config(bg=self.colors["PANEL"], fg=self.colors["MUTED"])
        self.log.config(bg=self.colors["PANEL"], fg=self.colors["TEXT"])
        self.log.tag_config("ok", foreground=self.colors["SUCCESS"])
        self.log.tag_config("err", foreground=self.colors["ERROR"])
        self.log.tag_config("warn", foreground=self.colors["WARNING"])
        self.log.tag_config("info", foreground=self.colors["ACCENT"])

        # Go button (mode aware)
        m = self.mode.get()
        accent = self.colors["ACCENT"] if m == "encrypt" else self.colors["ACCENT2"]
        active = self.colors["ACCENT_ACTIVE"] if m == "encrypt" else self.colors["ACCENT2_ACTIVE"]
        self.go_btn.config(bg=accent, activebackground=active)

        # Progress
        style = ttk.Style(self)
        style.configure("TProgressbar", troughcolor=self.colors["PANEL"],
                        background=self.colors["ACCENT"])

    def _on_mode_change(self, *_):
        m = self.mode.get()
        if m == "encrypt":
            self.go_btn.config(text="🔒  ENCRYPT",
                               bg=self.colors["ACCENT"],
                               activebackground=self.colors["ACCENT_ACTIVE"])
            self.confirm_label.config(fg=self.colors["MUTED"])
            self.confirm_entry.config(state="normal")
        else:
            self.go_btn.config(text="🔓  DECRYPT",
                               bg=self.colors["ACCENT2"],
                               activebackground=self.colors["ACCENT2_ACTIVE"])
            self.confirm_label.config(fg=self.colors["MUTED"])
            self.confirm_entry.config(state="disabled")
        self._clear_files()

    # ── run ───────────────────────────────────────────────────────────────────
    def _run(self):
        if not self.files:
            messagebox.showwarning("No Files", "Please add at least one file.")
            return
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("No Password", "Please enter a password.")
            return
        if self.mode.get() == "encrypt":
            if pw != self.confirm_var.get():
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return

        self.go_btn.config(state="disabled")
        threading.Thread(target=self._process,
                         args=(self.mode.get(), pw, self.keyfile_var.get()),
                         daemon=True).start()

    def _process(self, mode, password, keyfile_path):
        total = len(self.files)
        success, failed = 0, 0
        delete = self.delete_orig.get()

        self._log(f"\n── Starting {mode.upper()} of {total} file(s) ──", "info")
        self.progress["value"] = 0

        for i, filepath in enumerate(self.files):
            name = Path(filepath).name
            try:
                if mode == "encrypt":
                    if filepath.endswith(ENC_SUFFIX):
                        self._log(f"⚠  Skipped (already encrypted): {name}", "warn")
                        continue
                    out = encrypt_file(filepath, password, keyfile_path)
                else:
                    if not filepath.endswith(ENC_SUFFIX):
                        self._log(f"⚠  Skipped (not .enc): {name}", "warn")
                        continue
                    out = decrypt_file(filepath, password, keyfile_path)

                self._log(f"✅ {name} → {Path(out).name}", "ok")
                success += 1
                if delete:
                    os.remove(filepath)
                    self._log(f"   🗑 Deleted original: {name}", "warn")

            except Exception as e:
                self._log(f"❌ {name}: {e}", "err")
                failed += 1

            self.progress["value"] = int((i + 1) / total * 100)

        self._log(f"\n── Done: {success} succeeded, {failed} failed ──", "info")
        self.go_btn.config(state="normal")

        summary = f"{success}/{total} file(s) processed successfully."
        if failed:
            summary += f"\n{failed} failed — check log."
        messagebox.showinfo("Complete", summary)

    # ── tray & close ──────────────────────────────────────────────────────────
    def _handle_close(self):
        if self.tray_enabled.get():
            self._minimize_to_tray()
        else:
            self.destroy()

    def _minimize_to_tray(self):
        self.withdraw()
        if not self.tray_icon:
            self._create_tray_icon()

    def _create_tray_icon(self):
        image = Image.new("RGB", (128, 128), color="#161920")
        draw = ImageDraw.Draw(image)
        # simple lock icon
        draw.rectangle((42, 55, 86, 85), fill=self.colors["ACCENT"])
        draw.rectangle((55, 40, 73, 55), fill=self.colors["ACCENT"])

        menu = pystray.Menu(
            pystray.MenuItem("Restore FileVault", self._restore_from_tray, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit_from_tray)
        )
        self.tray_icon = pystray.Icon("filevault", image, "FileVault AES-256", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _restore_from_tray(self, *args):
        self.deiconify()
        self.lift()
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except:
                pass
            self.tray_icon = None

    def _quit_from_tray(self, *args):
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except:
                pass
        self.destroy()


if __name__ == "__main__":
    app = EncryptApp()
    app.mainloop()