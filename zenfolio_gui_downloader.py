#!/usr/bin/env python3
"""
Zenfolio GUI Gallery Downloader
--------------------------------
A Tkinter-based GUI to download images from a Zenfolio gallery (new & classic sites)
using the public JSON-RPC API. Paste a gallery URL, choose an output directory,
and optionally provide an owner login (to access originals) or a gallery password.

Features
- Paste gallery URL and choose output directory
- Optional gallery password (client protected galleries)
- Optional owner login (username/password) to fetch originals when allowed
- Analyze first (lists photos, counts), then Download
- Filename template support: e.g. "{sequence}_{title}.jpg"
  tokens: {id}, {sequence}, {filename}, {title}, {ext}, {date:%Y%m%d}, {index}
- Preferred size selection: Original, Largest, 3XL, 2XL, XL
- Skip existing files, Dry-run mode, Concurrent downloads
- Progress bar, live status log, cancel button
- Manifest CSV export
- Robust error messages

Dependencies
- Standard library + requests (pip install requests)
"""

import argparse
import csv
import json
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

API_URL = "https://api.zenfolio.com/api/1.8/zfapi.asmx"
HEADERS = {"Content-Type": "application/json"}

# --------------------------
# Zenfolio API Helpers
# --------------------------

def extract_photoset_id(gallery_url: str) -> int:
    """
    Accepts URLs like:
      https://example.zenfolio.com/p123456789
      https://example.zenfolio.com/p123456789?custom=1
      https://example.zenfolio.com/p-123456789
    Returns integer photoset id.
    """
    path = urlparse(gallery_url).path
    m = re.search(r"/p[-]?(\d+)", path)
    if not m:
        raise ValueError(f"Could not find photoset id in URL: {gallery_url}")
    return int(m.group(1))

def rpc(method: str, params=None, auth_token: Optional[str]=None):
    payload = {"method": method, "params": params or [], "id": 1}
    headers = HEADERS.copy()
    if auth_token:
        headers["X-Zenfolio-Token"] = auth_token
    r = requests.post(API_URL, headers=headers, data=json.dumps(payload), timeout=30)
    r.raise_for_status()
    data = r.json()
    if "error" in data and data["error"]:
        raise RuntimeError(f"Zenfolio API error: {data['error']}")
    return data["result"]

def login_owner(username: str, password: str) -> str:
    """Owner login -> auth token string."""
    return rpc("Login", [username, password])

def load_photos(photoset_id: int,
                auth_token: Optional[str]=None,
                gallery_password: Optional[str]=None,
                page_size: int = 200) -> List[Dict[str, Any]]:
    photos = []
    idx = 0
    while True:
        params = [photoset_id, idx, page_size]
        if gallery_password:
            params.append(gallery_password)
        batch = rpc("LoadPhotoSetPhotos", params, auth_token=auth_token)
        if not batch:
            break
        photos.extend(batch)
        if len(batch) < page_size:
            break
        idx += page_size
    return photos

# --------------------------
# URL Selection / Filename
# --------------------------

SIZE_PREFS = {
    "Original": None,  # Use OriginalUrl if available
    "Largest": "largest",
    "3XL": 6,
    "2XL": 5,
    "XL": 4,
}

def construct_sized_url(photo: Dict[str, Any], size_code: int) -> Optional[str]:
    url_host = photo.get("UrlHost")
    url_core = photo.get("UrlCore")
    seq = photo.get("Sequence")
    token = photo.get("UrlToken")
    if url_host and url_core is not None and seq is not None:
        parts = [url_host.rstrip("/"), "img", str(url_core).lstrip("/"), str(size_code), str(seq)]
        if token:
            parts.append(str(token))
        return "/".join(parts)
    return None

def choose_download_url(photo: Dict[str, Any], pref) -> Optional[str]:
    """
    Choose the best URL according to preference.
    pref can be None (Original), "largest", or an int size code (6,5,4).
    """
    # Prefer Original when explicitly asked
    if pref is None:
        if photo.get("OriginalUrl"):
            return photo["OriginalUrl"]
        # fall back to largest
        pref = "largest"

    if pref == "largest":
        # API may expose LargestImageUrl or a set of named sizes
        for key in ("LargestImageUrl", "UrlXXXL", "UrlXXL", "UrlXL", "UrlL"):
            u = photo.get(key)
            if u:
                return u
        # try constructing 6, then 5, then 4
        for sc in (6, 5, 4):
            u = construct_sized_url(photo, sc)
            if u:
                return u
        return None

    if isinstance(pref, int):
        u = construct_sized_url(photo, pref)
        if u:
            return u
        # fallback to largest
        return choose_download_url(photo, "largest")

    return None

def safe_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = name.strip().strip(".")
    return name or "file"

def get_ext_from_url(url: str, default=".jpg") -> str:
    path = urlparse(url).path
    base = os.path.basename(path)
    if "." in base:
        return "." + base.split(".")[-1].split("?")[0]
    return default

def format_filename(template: str, photo: Dict[str, Any], url: str, index: int) -> str:
    # Gather fields
    pid = photo.get("Id") or ""
    seq = photo.get("Sequence")
    filename = photo.get("FileName") or ""
    title = photo.get("Title") or ""
    ext = get_ext_from_url(url) or ".jpg"

    # date token (PhotoDate, if available, else blank)
    # API sometimes returns PhotoDate like "/Date(1697321234567)/"
    date_raw = photo.get("PhotoDate") or photo.get("CapturedOn") or ""
    fmt_date = ""
    if isinstance(date_raw, str):
        m = re.search(r"/Date\((\d+)\)/", date_raw)
        if m:
            try:
                ts_ms = int(m.group(1))
                fmt_date = time.strftime("%Y%m%d", time.gmtime(ts_ms / 1000))
            except Exception:
                fmt_date = ""
    # default tokens
    mapping = {
        "id": str(pid),
        "sequence": str(seq if seq is not None else ""),
        "filename": os.path.splitext(filename)[0],
        "title": title,
        "ext": ext,
        "index": f"{index:04d}",
        # date subformat handled below
    }

    def repl(m):
        inner = m.group(1)  # e.g., date:%Y-%m
        if inner.startswith("date:"):
            # allow custom date formatting if we have a date
            if fmt_date:
                # we have only yyyymmdd; build a struct_time
                try:
                    t = time.strptime(fmt_date, "%Y%m%d")
                except Exception:
                    return ""
                spec = inner.split("date:", 1)[1]
                try:
                    return time.strftime(spec, t)
                except Exception:
                    return fmt_date
            return ""
        else:
            return mapping.get(inner, "")

    # Replace {token} or {date:%Y-%m-%d}
    out = re.sub(r"\{([^}]+)\}", repl, template)
    out = safe_filename(out)
    # ensure extension
    if not out.lower().endswith(ext.lower()):
        out += ext
    return out

# --------------------------
# Data classes
# --------------------------

@dataclass
class PhotoItem:
    raw: Dict[str, Any]
    url: str
    name: str
    status: str = "Queued"
    error: Optional[str] = None

# --------------------------
# GUI App
# --------------------------

class ZenfolioGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Zenfolio Gallery Downloader")
        self.geometry("980x700")
        self.minsize(900, 620)

        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.auth_token: Optional[str] = None
        self.photo_items: List[PhotoItem] = []
        self.output_dir = tk.StringVar(value=str(Path.cwd() / "zenfolio_downloads"))
        self.url_var = tk.StringVar()
        self.gallery_pass_var = tk.StringVar()
        self.owner_user_var = tk.StringVar()
        self.owner_pass_var = tk.StringVar()
        self.show_pass = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=False)
        self.skip_existing_var = tk.BooleanVar(value=True)
        self.concurrent_var = tk.IntVar(value=4)
        self.size_pref_var = tk.StringVar(value="Largest")
        self.template_var = tk.StringVar(value="{sequence}_{filename}{ext}")
        self.manifest_on_finish = tk.BooleanVar(value=True)

        self._build_ui()

    # UI layout
    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        # Top frame: inputs
        top = ttk.LabelFrame(self, text="Gallery & Output")
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Gallery URL:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.url_var, width=70).grid(row=0, column=1, columnspan=3, sticky="we", padx=(6,6))
        ttk.Label(top, text="Output Folder:").grid(row=1, column=0, sticky="w")
        out_entry = ttk.Entry(top, textvariable=self.output_dir, width=60)
        out_entry.grid(row=1, column=1, sticky="we", padx=(6,6))
        ttk.Button(top, text="Browse…", command=self._choose_dir).grid(row=1, column=2, sticky="w")

        # Options
        opts = ttk.LabelFrame(self, text="Options")
        opts.pack(fill="x", **pad)

        ttk.Label(opts, text="Gallery password (optional):").grid(row=0, column=0, sticky="w")
        ttk.Entry(opts, textvariable=self.gallery_pass_var, width=24, show="*").grid(row=0, column=1, sticky="w")

        ttk.Label(opts, text="Owner username (optional):").grid(row=0, column=2, sticky="e")
        ttk.Entry(opts, textvariable=self.owner_user_var, width=24).grid(row=0, column=3, sticky="w")

        ttk.Label(opts, text="Owner password (optional):").grid(row=0, column=4, sticky="e")
        self.pass_entry = ttk.Entry(opts, textvariable=self.owner_pass_var, width=24, show="*")
        self.pass_entry.grid(row=0, column=5, sticky="w")
        ttk.Checkbutton(opts, text="Show", variable=self.show_pass, command=self._toggle_pass).grid(row=0, column=6, sticky="w")

        ttk.Label(opts, text="Preferred size:").grid(row=1, column=0, sticky="e", pady=(8,0))
        size_cb = ttk.Combobox(opts, textvariable=self.size_pref_var, values=list(SIZE_PREFS.keys()), state="readonly", width=12)
        size_cb.grid(row=1, column=1, sticky="w", pady=(8,0))

        ttk.Label(opts, text="Filename template:").grid(row=1, column=2, sticky="e", pady=(8,0))
        ttk.Entry(opts, textvariable=self.template_var, width=36).grid(row=1, column=3, sticky="w", pady=(8,0))
        ttk.Button(opts, text="?", width=3, command=self._show_template_help).grid(row=1, column=4, sticky="w", pady=(8,0))

        ttk.Label(opts, text="Concurrent downloads:").grid(row=1, column=5, sticky="e", pady=(8,0))
        spin = ttk.Spinbox(opts, from_=1, to=10, textvariable=self.concurrent_var, width=5)
        spin.grid(row=1, column=6, sticky="w", pady=(8,0))

        ttk.Checkbutton(opts, text="Skip existing", variable=self.skip_existing_var).grid(row=2, column=0, sticky="w", pady=(6,0))
        ttk.Checkbutton(opts, text="Dry run (don’t save files)", variable=self.dry_run_var).grid(row=2, column=1, sticky="w", pady=(6,0))
        ttk.Checkbutton(opts, text="Export manifest on finish", variable=self.manifest_on_finish).grid(row=2, column=2, sticky="w", pady=(6,0))

        for i in range(7):
            opts.grid_columnconfigure(i, weight=1)
        for i in range(4):
            top.grid_columnconfigure(i, weight=1)

        # Action buttons
        actions = ttk.Frame(self)
        actions.pack(fill="x", **pad)
        self.analyze_btn = ttk.Button(actions, text="Analyze Gallery", command=self._on_analyze)
        self.analyze_btn.pack(side="left")
        self.start_btn = ttk.Button(actions, text="Start Download", command=self._on_start, state="disabled")
        self.start_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(actions, text="Stop", command=self._on_stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.open_btn = ttk.Button(actions, text="Open Output Folder", command=self._open_output)
        self.open_btn.pack(side="right")

        # Table
        table_frame = ttk.LabelFrame(self, text="Queue")
        table_frame.pack(fill="both", expand=True, **pad)

        cols = ("index", "name", "status")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=16)
        self.tree.heading("index", text="#")
        self.tree.heading("name", text="File name")
        self.tree.heading("status", text="Status")
        self.tree.column("index", width=60, anchor="center")
        self.tree.column("name", width=560, anchor="w")
        self.tree.column("status", width=200, anchor="w")
        self.tree.pack(fill="both", expand=True, side="left")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        sb.pack(side="right", fill="y")

        # Progress + Log
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", **pad)
        self.prog = ttk.Progressbar(bottom, orient="horizontal", mode="determinate")
        self.prog.pack(fill="x", expand=True, side="left")
        self.prog_label = ttk.Label(bottom, text="Idle")
        self.prog_label.pack(side="left", padx=8)

        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="both", expand=False, **pad)
        self.log = tk.Text(log_frame, height=10, wrap="word")
        self.log.pack(fill="both", expand=True)

    def _choose_dir(self):
        d = filedialog.askdirectory(initialdir=self.output_dir.get())
        if d:
            self.output_dir.set(d)

    def _toggle_pass(self):
        self.pass_entry.config(show="" if self.show_pass.get() else "*")

    def _show_template_help(self):
        msg = (
            "Filename template tokens:\n"
            "  {id}          -> Zenfolio photo ID\n"
            "  {sequence}    -> sequence number in the gallery\n"
            "  {filename}    -> original file base name (without extension)\n"
            "  {title}       -> photo title (if any)\n"
            "  {ext}         -> file extension derived from URL\n"
            "  {index}       -> running index (zero-padded)\n"
            "  {date:%Y%m%d} -> capture date (if available) with custom strftime format\n\n"
            "Examples:\n"
            "  {sequence}_{filename}{ext}\n"
            "  {date:%Y-%m-%d}_{title}{ext}\n"
            "  {index}_{id}{ext}\n"
        )
        messagebox.showinfo("Filename Templates", msg)

    # Logging helpers
    def _log(self, text: str):
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")

    def _set_status(self, text: str):
        self.prog_label.config(text=text)

    # Actions
    def _on_analyze(self):
        try:
            self._analyze_gallery()
        except Exception as e:
            messagebox.showerror("Analyze failed", str(e))

    def _analyze_gallery(self):
        url = self.url_var.get().strip()
        if not url:
            raise ValueError("Please enter a gallery URL.")
        out = Path(self.output_dir.get()).expanduser()
        out.mkdir(parents=True, exist_ok=True)

        self._log(f"[+] Parsing photoset id from URL: {url}")
        pid = extract_photoset_id(url)
        self._log(f"[+] Photoset ID: {pid}")

        # Login if owner creds provided
        self.auth_token = None
        owner_user = self.owner_user_var.get().strip()
        owner_pass = self.owner_pass_var.get()
        if owner_user and owner_pass:
            self._log("[*] Logging in as owner...")
            try:
                self.auth_token = login_owner(owner_user, owner_pass)
                self.session.headers.update({"X-Zenfolio-Token": self.auth_token})
                self._log("[✓] Owner login successful")
            except Exception as e:
                self._log(f"[!] Owner login failed: {e}")
                messagebox.showwarning("Owner login failed", f"{e}")

        # Load photos
        self._log("[*] Loading gallery photo list...")
        photos = load_photos(pid, auth_token=self.auth_token, gallery_password=self.gallery_pass_var.get().strip() or None)
        if not photos:
            raise RuntimeError("No photos returned. Check URL/password/permissions.")

        self._log(f"[✓] Found {len(photos)} photos.")
        # Build items with chosen URLs
        size_pref = SIZE_PREFS.get(self.size_pref_var.get(), "largest")

        items: List[PhotoItem] = []
        for i, p in enumerate(photos, start=1):
            u = choose_download_url(p, size_pref)
            if not u:
                continue
            fname = format_filename(self.template_var.get().strip() or "{sequence}_{filename}{ext}", p, u, i)
            items.append(PhotoItem(raw=p, url=u, name=fname))

        self.photo_items = items
        self._refresh_table()
        self.start_btn.config(state="normal")
        self._set_status(f"Ready ({len(items)} files)")

    def _refresh_table(self):
        # clear
        for row in self.tree.get_children():
            self.tree.delete(row)
        # insert
        for i, it in enumerate(self.photo_items, start=1):
            self.tree.insert("", "end", values=(i, it.name, it.status))

    def _on_start(self):
        if not self.photo_items:
            messagebox.showinfo("Nothing to download", "Analyze a gallery first.")
            return
        self.stop_event.clear()
        self.analyze_btn.config(state="disabled")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        threading.Thread(target=self._download_worker, daemon=True).start()

    def _on_stop(self):
        self.stop_event.set()
        self._log("[*] Cancel requested. Waiting for active downloads to finish...")

    def _open_output(self):
        path = Path(self.output_dir.get()).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore
            elif os.name == "posix":
                import subprocess
                subprocess.Popen(["xdg-open", str(path)])
            else:
                messagebox.showinfo("Open folder", str(path))
        except Exception as e:
            messagebox.showinfo("Open folder", f"{path}\n\n{e}")

    def _download_worker(self):
        total = len(self.photo_items)
        out_dir = Path(self.output_dir.get()).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)

        self.prog["maximum"] = total
        self.prog["value"] = 0
        done = 0

        dry = self.dry_run_var.get()
        skip = self.skip_existing_var.get()
        workers = max(1, min(10, self.concurrent_var.get()))

        self._set_status("Starting downloads..." if not dry else "Dry run...")
        self._log(f"[*] Workers: {workers} | Skip existing: {skip} | Dry-run: {dry}")
        size_pref = SIZE_PREFS.get(self.size_pref_var.get(), "largest")

        def download_one(idx: int, item: PhotoItem):
            if self.stop_event.is_set():
                return "Cancelled"
            dest = out_dir / item.name
            # Skip existing
            if skip and dest.exists() and dest.stat().st_size > 0:
                item.status = "Skipped (exists)"
                return "Skipped"

            if dry:
                item.status = "Would download"
                return "Dry"

            try:
                with self.session.get(item.url, stream=True, timeout=60) as r:
                    if r.status_code != 200:
                        raise RuntimeError(f"HTTP {r.status_code}")
                    tmp = dest.with_suffix(dest.suffix + ".part")
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1024 * 256):
                            if self.stop_event.is_set():
                                item.status = "Cancelled"
                                return "Cancelled"
                            if chunk:
                                f.write(chunk)
                    tmp.rename(dest)
                item.status = "OK"
                return "OK"
            except Exception as e:
                item.status = "Error"
                item.error = str(e)
                return f"Error: {e}"

        results = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_to_idx = {ex.submit(download_one, i, it): i for i, it in enumerate(self.photo_items, start=1)}
            for fut in as_completed(future_to_idx):
                idx = future_to_idx[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = f"Error: {e}"
                results.append((idx, res))
                done += 1
                self.prog["value"] = done
                self._refresh_table()
                self._set_status(f"{done}/{total}")

                # log each completion
                it = self.photo_items[idx-1]
                self._log(f"[{idx:04d}] {it.name} -> {it.status}" + (f" ({it.error})" if it.error else ""))

                if self.stop_event.is_set():
                    # Draining remaining futures not necessary; they will finish soon
                    pass

        # Export manifest
        if self.manifest_on_finish.get():
            self._export_manifest(out_dir)

        self._set_status("Done")
        self.analyze_btn.config(state="normal")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _export_manifest(self, out_dir: Path):
        rows = []
        for i, it in enumerate(self.photo_items, start=1):
            p = it.raw
            rows.append({
                "index": i,
                "filename": it.name,
                "status": it.status,
                "error": it.error or "",
                "url": it.url,
                "id": p.get("Id", ""),
                "sequence": p.get("Sequence", ""),
                "title": p.get("Title", ""),
                "fileNameOrig": p.get("FileName", ""),
                "photoDate": p.get("PhotoDate", ""),
            })
        manifest = out_dir / "manifest.csv"
        with open(manifest, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        self._log(f"[✓] Manifest written: {manifest}")

def main():
    app = ZenfolioGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
