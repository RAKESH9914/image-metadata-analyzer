# Image Metadata Analyzer

Extracts EXIF/metadata from images and flags forensic and privacy issues.

## Features
- EXIF extraction (camera, date, software, etc.) and GPS to map link
- MD5 + SHA-256 hashes (file integrity)
- File signature check (detects fake extensions, e.g. .jpg that is really .png)
- Findings: GPS leak, edited-with-software, modified date mismatch, stripped EXIF
- Risk level: LOW / MEDIUM / HIGH
- Compare two images: MD5 / SHA-1 / SHA-256, perceptual hash similarity %, and a side-by-side metadata difference table
- Web UI: image preview, key-facts cards, searchable EXIF table, copy-hash buttons, JSON report download
- CLI (single file or folder) with JSON and CSV export, plus Flask web UI

## Setup
    pip install -r requirements.txt

## Run
    python main.py photo.jpg
    python main.py my_images/ --json report.json --csv report.csv
    python main.py --compare original.jpg copy.jpg
    python app.py        # then open http://127.0.0.1:5000

## Structure
    analyzer.py   core logic
    main.py       command-line tool
    app.py        Flask web app
    templates/    HTML page
