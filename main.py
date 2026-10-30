"""CLI:  python main.py photo.jpg   |   python main.py folder/ --json out.json --csv out.csv"""
import argparse
import csv
import json
import os
from analyzer import analyze, compare

IMG_EXT = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp")


def collect(target):
    if os.path.isfile(target):
        return [target]
    return [os.path.join(target, f) for f in sorted(os.listdir(target))
            if f.lower().endswith(IMG_EXT)]


def show(r):
    print("=" * 60)
    print(f"File     : {r['file']}  ({r['size_kb']} KB)")
    print(f"Type     : {r['extension_type']} (real: {r['real_type']})")
    print(f"Size     : {r['width']} x {r['height']}  mode={r['mode']}")
    print(f"MD5      : {r['hashes']['md5']}")
    print(f"SHA-1    : {r['hashes']['sha1']}")
    print(f"SHA-256  : {r['hashes']['sha256']}")
    for k in ("Make", "Model", "DateTimeOriginal", "Software"):
        if k in r["exif"]:
            print(f"{k:<9}: {r['exif'][k]}")
    if r["gps"]:
        print(f"GPS      : {r['gps']['lat']}, {r['gps']['lon']}  -> {r['gps']['map']}")
    print(f"Risk     : {r['risk']}")
    for level, msg in r["flags"]:
        print(f"  [{level.upper()}] {msg}")
    if r["error"]:
        print("Error    :", r["error"])


def main():
    p = argparse.ArgumentParser(description="Image Metadata Analyzer")
    p.add_argument("target", nargs="?", help="image file or folder")
    p.add_argument("--compare", nargs=2, metavar=("IMG1", "IMG2"), help="compare two images by hash")
    p.add_argument("--json", help="save full report as JSON")
    p.add_argument("--csv", help="save summary as CSV")
    a = p.parse_args()

    if a.compare:
        c = compare(*a.compare)
        print("=" * 60)
        for row in c["hash_rows"]:
            print(f"{row['name']:<8} A: {row['a']}")
            print(f"{row['name']:<8} B: {row['b']}   {'MATCH' if row['same'] else 'DIFFERENT'}")
        print(f"Exact match: {'YES' if c['exact_match'] else 'NO'}")
        if c["similarity"] is not None:
            print(f"Perceptual hash: {c['phash_a']} vs {c['phash_b']}  ->  {c['similarity']}% similar")
        if c["error"]:
            print("Note:", c["error"])
        print("Verdict   :", c["verdict"])
        return
    if not a.target:
        p.error("give an image/folder, or use --compare IMG1 IMG2")

    files = collect(a.target)
    if not files:
        print("No images found.")
        return
    results = [analyze(f) for f in files]
    for r in results:
        show(r)

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\nJSON saved: {a.json}")
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["file", "real_type", "width", "height", "camera", "date_taken",
                        "gps", "sha256", "risk", "flags"])
            for r in results:
                cam = f"{r['exif'].get('Make', '')} {r['exif'].get('Model', '')}".strip()
                gps = f"{r['gps']['lat']},{r['gps']['lon']}" if r["gps"] else ""
                w.writerow([r["file"], r["real_type"], r["width"], r["height"], cam,
                            r["exif"].get("DateTimeOriginal", ""), gps,
                            r["hashes"]["sha256"], r["risk"],
                            "; ".join(m for _, m in r["flags"])])
        print(f"CSV saved: {a.csv}")


if __name__ == "__main__":
    main()
