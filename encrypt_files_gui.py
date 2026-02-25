#!/usr/bin/env python3
"""
encrypt_files_gui.py — AES-256 File Encryption Tool with GUI
Run: python encrypt_files_gui.py
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "--break-system-packages"])
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 600_000
ENC_SUFFIX = ".enc"
CHUNK_SIZE = 64 * 1024


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def encrypt_file(filepath: str, password: str) -> str:
    src = Path(filepath)
    dst = Path(str(src) + ENC_SUFFIX)
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)
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


def decrypt_file(filepath: str, password: str) -> str:
    src = Path(filepath)
    dst = Path(filepath[: -len(ENC_SUFFIX)])
    with open(src, "rb") as fin:
        salt = fin.read(SALT_SIZE)
        iv = fin.read(IV_SIZE)
        key = derive_key(password, salt)
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
                raise ValueError("Wrong password or corrupted file.")
    return str(dst)


# ─── GUI ──────────────────────────────────────────────────────────────────────

BG        = "#0d0f14"
PANEL     = "#161920"
BORDER    = "#252a35"
ACCENT    = "#00e5ff"
ACCENT2   = "#7c3aed"
TEXT      = "#e8eaf0"
MUTED     = "#6b7280"
SUCCESS   = "#22c55e"
ERROR     = "#ef4444"
WARNING   = "#f59e0b"
FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_HEAD = ("Segoe UI Semibold", 11)


class EncryptApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FileVault — AES-256 Encryption")
        self.geometry("780x620")
        self.minsize(680, 520)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.files: list[str] = []
        self.mode = tk.StringVar(value="encrypt")

        self._build_ui()

    # ── layout ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── header bar
        header = tk.Frame(self, bg=PANEL, height=56)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header, text="🔐  FileVault", font=("Segoe UI Semibold", 15),
            fg=ACCENT, bg=PANEL, padx=20
        ).pack(side="left", pady=12)

        tk.Label(
            header, text="AES-256-CBC · PBKDF2-SHA256",
            font=("Segoe UI", 9), fg=MUTED, bg=PANEL
        ).pack(side="left", pady=14)

        # ── main body
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=14)

        # left column
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self._section(left, "MODE")
        mode_row = tk.Frame(left, bg=BG)
        mode_row.pack(fill="x", pady=(0, 12))
        for label, val in [("Encrypt files", "encrypt"), ("Decrypt .enc files", "decrypt")]:
            self._radio(mode_row, label, val)

        self._section(left, "FILES")
        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill="x", pady=(0, 6))
        self._btn(btn_row, "＋ Add Files", self._add_files, ACCENT, "#00000000").pack(side="left", padx=(0, 6))
        self._btn(btn_row, "✕ Remove Selected", self._remove_selected, ERROR, "#00000000").pack(side="left", padx=(0, 6))
        self._btn(btn_row, "Clear All", self._clear_files, MUTED, "#00000000").pack(side="left")

        list_frame = tk.Frame(left, bg=PANEL, bd=0, highlightthickness=1,
                              highlightbackground=BORDER)
        list_frame.pack(fill="both", expand=True, pady=(0, 4))

        scrollbar = tk.Scrollbar(list_frame, bg=PANEL, troughcolor=PANEL,
                                 activebackground=ACCENT, relief="flat", bd=0, width=10)
        scrollbar.pack(side="right", fill="y")

        self.file_list = tk.Listbox(
            list_frame, bg=PANEL, fg=TEXT, selectbackground=ACCENT2,
            selectforeground="white", font=FONT_MONO, bd=0, highlightthickness=0,
            activestyle="none", selectmode="extended",
            yscrollcommand=scrollbar.set
        )
        self.file_list.pack(fill="both", expand=True, padx=8, pady=6)
        scrollbar.config(command=self.file_list.yview)

        self.file_count = tk.Label(left, text="No files added", font=("Segoe UI", 9),
                                   fg=MUTED, bg=BG, anchor="w")
        self.file_count.pack(fill="x")

        # right column
        right = tk.Frame(body, bg=BG, width=230)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        self._section(right, "PASSWORD")

        tk.Label(right, text="Password", font=FONT_UI, fg=MUTED, bg=BG, anchor="w").pack(fill="x")
        self.pw_var = tk.StringVar()
        self.pw_entry = self._entry(right, self.pw_var, show="●")
        self.pw_entry.pack(fill="x", pady=(2, 10))

        self.confirm_label = tk.Label(right, text="Confirm Password", font=FONT_UI,
                                      fg=MUTED, bg=BG, anchor="w")
        self.confirm_label.pack(fill="x")
        self.confirm_var = tk.StringVar()
        self.confirm_entry = self._entry(right, self.confirm_var, show="●")
        self.confirm_entry.pack(fill="x", pady=(2, 4))

        self.show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(
            right, text="Show passwords", variable=self.show_pw,
            command=self._toggle_show, font=("Segoe UI", 9),
            fg=MUTED, bg=BG, activebackground=BG, activeforeground=TEXT,
            selectcolor=PANEL, bd=0, highlightthickness=0
        ).pack(anchor="w", pady=(0, 14))

        self._section(right, "OPTIONS")
        self.delete_orig = tk.BooleanVar(value=False)
        tk.Checkbutton(
            right, text="Delete originals after\nsuccessful operation",
            variable=self.delete_orig, font=("Segoe UI", 9),
            fg=TEXT, bg=BG, activebackground=BG, activeforeground=TEXT,
            selectcolor=PANEL, bd=0, highlightthickness=0, justify="left", wraplength=200
        ).pack(anchor="w", pady=(0, 18))

        self.go_btn = tk.Button(
            right, text="🔒  ENCRYPT", font=("Segoe UI Semibold", 12),
            bg=ACCENT, fg="#000000", activebackground="#00b8cc", activeforeground="#000",
            bd=0, padx=14, pady=10, cursor="hand2", command=self._run
        )
        self.go_btn.pack(fill="x", pady=(0, 4))

        self.mode.trace_add("write", self._on_mode_change)

        # ── log bar
        log_frame = tk.Frame(self, bg=PANEL, height=130)
        log_frame.pack(fill="x", padx=18, pady=(0, 14))
        log_frame.pack_propagate(False)

        log_head = tk.Frame(log_frame, bg=PANEL)
        log_head.pack(fill="x", padx=10, pady=(6, 2))
        tk.Label(log_head, text="LOG", font=("Segoe UI Semibold", 9),
                 fg=MUTED, bg=PANEL).pack(side="left")
        tk.Button(log_head, text="Clear", font=("Segoe UI", 8), fg=MUTED,
                  bg=PANEL, activebackground=PANEL, bd=0, cursor="hand2",
                  command=self._clear_log).pack(side="right")

        self.log = tk.Text(
            log_frame, bg=PANEL, fg=TEXT, font=FONT_MONO,
            bd=0, highlightthickness=0, state="disabled", wrap="word"
        )
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.log.tag_config("ok", foreground=SUCCESS)
        self.log.tag_config("err", foreground=ERROR)
        self.log.tag_config("warn", foreground=WARNING)
        self.log.tag_config("info", foreground=ACCENT)

        # ── progress bar
        self.progress = ttk.Progressbar(self, mode="determinate", maximum=100)
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TProgressbar", troughcolor=PANEL, background=ACCENT,
                        bordercolor=PANEL, lightcolor=ACCENT, darkcolor=ACCENT)
        self.progress.pack(fill="x", padx=18, pady=(0, 10))

    # ── widget helpers ─────────────────────────────────────────────────────────

    def _section(self, parent, text):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", pady=(4, 4))
        tk.Label(f, text=text, font=("Segoe UI Semibold", 8),
                 fg=ACCENT, bg=BG).pack(side="left")
        tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x", expand=True, padx=(6, 0), pady=6)

    def _radio(self, parent, label, value):
        tk.Radiobutton(
            parent, text=label, variable=self.mode, value=value,
            font=FONT_UI, fg=TEXT, bg=BG, activebackground=BG,
            activeforeground=ACCENT, selectcolor=PANEL,
            bd=0, highlightthickness=0
        ).pack(side="left", padx=(0, 16))

    def _btn(self, parent, text, cmd, fg, bg):
        return tk.Button(
            parent, text=text, command=cmd, font=("Segoe UI", 9),
            fg=fg, bg=PANEL, activebackground=BORDER, activeforeground=fg,
            relief="flat", bd=0, padx=10, pady=5, cursor="hand2"
        )

    def _entry(self, parent, var, show=None):
        e = tk.Entry(
            parent, textvariable=var, font=FONT_MONO,
            bg=PANEL, fg=TEXT, insertbackground=ACCENT,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT,
            show=show
        )
        return e

    # ── actions ────────────────────────────────────────────────────────────────

    def _on_mode_change(self, *_):
        m = self.mode.get()
        if m == "encrypt":
            self.go_btn.config(text="🔒  ENCRYPT", bg=ACCENT, activebackground="#00b8cc")
            self.confirm_label.config(fg=MUTED)
            self.confirm_entry.config(state="normal")
        else:
            self.go_btn.config(text="🔓  DECRYPT", bg=ACCENT2, activebackground="#6d28d9")
            self.confirm_label.config(fg=MUTED)
            self.confirm_entry.config(state="disabled")
        self._clear_files()

    def _add_files(self):
        m = self.mode.get()
        if m == "encrypt":
            types = [("All files", "*.*")]
            title = "Select files to encrypt"
        else:
            types = [("Encrypted files", "*.enc"), ("All files", "*.*")]
            title = "Select .enc files to decrypt"

        picked = filedialog.askopenfilenames(title=title, filetypes=types)
        added = 0
        for f in picked:
            if f not in self.files:
                self.files.append(f)
                self.file_list.insert("end", Path(f).name + f"  [{self._size(f)}]")
                added += 1
        self._update_count()
        if added:
            self._log(f"Added {added} file(s).", "info")

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

    # ── run ────────────────────────────────────────────────────────────────────

    def _run(self):
        if not self.files:
            messagebox.showwarning("No Files", "Please add at least one file.")
            return

        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("No Password", "Please enter a password.")
            return

        m = self.mode.get()
        if m == "encrypt":
            confirm = self.confirm_var.get()
            if pw != confirm:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return

        self.go_btn.config(state="disabled")
        threading.Thread(target=self._process, args=(m, pw), daemon=True).start()

    def _process(self, mode, password):
        total = len(self.files)
        success, failed = 0, 0
        delete = self.delete_orig.get()

        self._log(f"\n── Starting {mode} of {total} file(s) ──", "info")
        self.progress["value"] = 0

        for i, filepath in enumerate(self.files):
            name = Path(filepath).name
            try:
                if mode == "encrypt":
                    if filepath.endswith(ENC_SUFFIX):
                        self._log(f"⚠  Skipped (already .enc): {name}", "warn")
                        continue
                    out = encrypt_file(filepath, password)
                else:
                    if not filepath.endswith(ENC_SUFFIX):
                        self._log(f"⚠  Skipped (not .enc): {name}", "warn")
                        continue
                    out = decrypt_file(filepath, password)

                self._log(f"✅ {name}  →  {Path(out).name}", "ok")
                success += 1

                if delete:
                    os.remove(filepath)
                    self._log(f"   🗑  Deleted original: {name}", "warn")

            except Exception as e:
                self._log(f"❌ {name}: {e}", "err")
                failed += 1

            self.progress["value"] = int((i + 1) / total * 100)

        self._log(f"\n── Done: {success} succeeded, {failed} failed ──", "info")
        self.go_btn.config(state="normal")

        summary = f"{success}/{total} file(s) processed successfully."
        if failed:
            summary += f"\n{failed} file(s) failed — check the log."
        messagebox.showinfo("Complete", summary)


if __name__ == "__main__":
    app = EncryptApp()
    app.mainloop()
