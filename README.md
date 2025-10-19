🖼️ Zenfolio Gallery Downloader (GUI)

A full-featured Python + Tkinter desktop app for downloading photos from any Zenfolio gallery — including the new layout — using Zenfolio’s official API.
Just paste a gallery URL, select a download folder, and start downloading!

👉 Live on GitHub: https://github.com/kennyroody/ZenfolioDownloader/tree/main

🚀 Features

✅ Modern GUI – Paste URL, choose folder, and click download
✅ Supports the new Zenfolio system (no brittle scraping)
✅ Owner login for downloading full-resolution originals (if permitted)
✅ Gallery password support for client-protected albums
✅ Dry-run mode to preview filenames before download
✅ Concurrent downloads (1–10 threads for speed)
✅ Skip existing files automatically
✅ Custom filename templates
✅ Preferred size selection – Original, Largest, 3XL, 2XL, XL
✅ Progress bar, live status log, and cancel button
✅ Manifest export (CSV) – includes all filenames, URLs, and statuses

🧠 How It Works

This app uses Zenfolio’s public JSON-RPC API:

https://api.zenfolio.com/api/1.8/zfapi.asmx


Key API methods:

Login — for owner authentication

LoadPhotoSetPhotos — to retrieve all gallery photos and metadata

It constructs valid URLs for each image (based on OriginalUrl, UrlHost, UrlCore, etc.)
and downloads them directly — with full respect to Zenfolio’s permission model.

🖥️ Installation
1️⃣ Clone or Download
git clone https://github.com/kennyroody/ZenfolioDownloader.git
cd ZenfolioDownloader

2️⃣ Install Requirements
pip install requests

3️⃣ Run the App
python zenfolio_gui_downloader.py

⚙️ GUI Options Overview
Option	Description
Gallery URL	Paste your Zenfolio gallery link (https://example.zenfolio.com/p123456789)
Output Folder	Choose where photos will be saved
Gallery Password	For password-protected galleries
Owner Username / Password	Authenticate to access originals
Preferred Size	Choose: Original, Largest, 3XL, 2XL, XL
Filename Template	Define naming pattern for downloaded files
Concurrent Downloads	1–10 threads
Skip Existing	Skip already-downloaded files
Dry Run	Preview only, no download
Export Manifest	CSV log of all photos, saved after completion
🧩 Filename Template Tokens
Token	Example	Description
{id}	123456	Zenfolio photo ID
{sequence}	42	Sequence number in gallery
{filename}	IMG_0012	Original filename
{title}	Sunset	Photo title
{ext}	.jpg	File extension
{index}	0001	Running index
{date:%Y%m%d}	20251018	Capture date (custom format allowed)
Example:
{date:%Y-%m-%d}_{title}{ext}

📦 Manifest CSV Output

After each download session, a file called manifest.csv is created in your output folder, listing:

index

filename

status

error (if any)

download URL

photo ID

sequence number

title

original filename

photo date

🛡️ Legal & Ethical Notice

Always respect the photographer’s permissions.

You can only download originals if allowed by the gallery settings or owner login.

This project complies with Zenfolio’s API Terms of Use
.

🧑‍💻 Development

Want to tweak or contribute?

pip install -r requirements.txt
python zenfolio_gui_downloader.py

💡 Roadmap

 Dark mode / theme selector

 Automatic retry for failed downloads

 Drag & drop gallery links

 Batch gallery import

 One-click EXE build via PyInstaller

🧾 License

MIT License © 2025 Kenneth N. Rood

You’re free to modify and redistribute — just credit the original author.
