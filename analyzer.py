"""Core logic: extract metadata from an image and flag suspicious/privacy items."""
import hashlib
import os
import datetime
from math import gcd
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# File signatures (magic bytes) -> real format
SIGNATURES = {
    b"\xff\xd8\xff": "jpeg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"BM": "bmp",
    b"II*\x00": "tiff",
    b"MM\x00*": "tiff",
}
EXT_MAP = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif",
           ".bmp": "bmp", ".tif": "tiff", ".tiff": "tiff", ".webp": "webp"}
EDITORS = ("photoshop", "gimp", "lightroom", "paint", "canva", "snapseed", "picsart")


def clean(v):
    """Make any EXIF value JSON/CSV friendly."""
    if isinstance(v, bytes):
        return v.decode("utf-8", "ignore").strip("\x00")[:200]
    if isinstance(v, (tuple, list)):
        return [clean(x) for x in v]
    if isinstance(v, (int, float, str)):
        return v
    try:
        return float(v)
    except Exception:
        return str(v)


def file_hashes(path):
    md5, sha1, sha = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha.hexdigest()}


def detect_real_type(path):
    with open(path, "rb") as f:
        head = f.read(16)
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    for sig, name in SIGNATURES.items():
        if head.startswith(sig):
            return name
    return "unknown"


def extract_exif(img):
    exif = img.getexif()
    data, gps = {}, {}
    for tid, val in exif.items():
        data[TAGS.get(tid, tid)] = clean(val)
    try:
        for tid, val in exif.get_ifd(0x8769).items():  # Exif sub-IFD
            data[TAGS.get(tid, tid)] = clean(val)
    except Exception:
        pass
    try:
        for tid, val in exif.get_ifd(0x8825).items():  # GPS IFD
            gps[GPSTAGS.get(tid, tid)] = val
    except Exception:
        pass
    data.pop("MakerNote", None)
    return data, gps


def _to_deg(v):
    d, m, s = [float(x) for x in v]
    return d + m / 60 + s / 3600


def gps_to_coords(gps):
    try:
        lat = _to_deg(gps["GPSLatitude"])
        lon = _to_deg(gps["GPSLongitude"])
        if gps.get("GPSLatitudeRef") == "S":
            lat = -lat
        if gps.get("GPSLongitudeRef") == "W":
            lon = -lon
        return {"lat": round(lat, 6), "lon": round(lon, 6),
                "map": f"https://www.google.com/maps?q={lat},{lon}"}
    except Exception:
        return None


def build_flags(ext_type, real_type, exif, coords):
    flags = []  # (level, message)
    if real_type == "unknown":
        flags.append(("high", "File signature not recognised - may not be a real image"))
    elif ext_type and ext_type != real_type:
        flags.append(("high", f"Extension says '{ext_type}' but real format is '{real_type}'"))
    if not exif:
        flags.append(("low", "No EXIF data (screenshot, web image, or metadata stripped)"))
    if coords:
        flags.append(("medium", "GPS location embedded - privacy risk if shared"))
    software = str(exif.get("Software", "")).lower()
    if any(e in software for e in EDITORS):
        flags.append(("medium", f"Edited with software: {exif.get('Software')}"))
    if exif.get("DateTime") and exif.get("DateTimeOriginal") and \
            exif["DateTime"] != exif["DateTimeOriginal"]:
        flags.append(("medium", "Modified date differs from original capture date"))
    return flags


def risk_level(flags):
    levels = [f[0] for f in flags]
    if "high" in levels:
        return "HIGH"
    if "medium" in levels:
        return "MEDIUM"
    return "LOW"


def build_summary(r):
    """Friendly key facts shown as cards in the web UI."""
    e, w, h = r["exif"], r["width"], r["height"]
    items = []

    def add(k, v):
        if v not in (None, ""):
            items.append([k, v])

    if w and h:
        add("Dimensions", f"{w} \u00d7 {h}")
        add("Megapixels", f"{w * h / 1e6:.2f} MP")
        g = gcd(w, h)
        a, b = w // g, h // g
        add("Aspect ratio", f"{a}:{b}" if max(a, b) <= 30 else f"{w / h:.2f}:1")
    add("Format", r["real_type"].upper())
    add("File size", f"{r['size_kb']} KB")
    add("Camera", f"{e.get('Make', '')} {e.get('Model', '')}".strip())
    add("Date taken", e.get("DateTimeOriginal") or e.get("DateTime"))
    add("ISO", e.get("ISOSpeedRatings") or e.get("PhotographicSensitivity"))
    et = e.get("ExposureTime")
    if isinstance(et, (int, float)) and et > 0:
        add("Exposure", f"1/{round(1 / et)} s" if et < 1 else f"{et:g} s")
    fn = e.get("FNumber")
    if isinstance(fn, (int, float)):
        add("Aperture", f"f/{fn:g}")
    fl = e.get("FocalLength")
    if isinstance(fl, (int, float)):
        add("Focal length", f"{fl:g} mm")
    add("Software", e.get("Software"))
    return items


def analyze(path):
    st = os.stat(path)
    ext = os.path.splitext(path)[1].lower()
    real = detect_real_type(path)
    result = {
        "file": os.path.basename(path),
        "size_kb": round(st.st_size / 1024, 2),
        "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "extension_type": EXT_MAP.get(ext, ext),
        "real_type": real,
        "hashes": file_hashes(path),
        "width": None, "height": None, "mode": None,
        "exif": {}, "gps": None, "summary": [], "flags": [], "risk": "LOW", "error": None,
    }
    try:
        with Image.open(path) as img:
            result["width"], result["height"] = img.size
            result["mode"] = img.mode
            exif, gps = extract_exif(img)
            result["exif"] = exif
            result["gps"] = gps_to_coords(gps)
    except Exception as e:
        result["error"] = f"Cannot open as image: {e}"
    result["summary"] = build_summary(result)
    result["flags"] = build_flags(result["extension_type"], real, result["exif"], result["gps"])
    result["risk"] = risk_level(result["flags"])
    return result


def perceptual_hash(path, size=8):
    """dHash: 64-bit fingerprint of how the image looks (survives resize/recompress)."""
    with Image.open(path) as img:
        px = list(img.convert("L").resize((size + 1, size), Image.LANCZOS).getdata())
    bits = ""
    for row in range(size):
        for col in range(size):
            i = row * (size + 1) + col
            bits += "1" if px[i] > px[i + 1] else "0"
    return f"{int(bits, 2):016x}"


def _details(r):
    e = r["exif"]
    return {
        "Format": r["real_type"].upper(),
        "Dimensions": f"{r['width']} \u00d7 {r['height']}" if r["width"] else "\u2014",
        "File size": f"{r['size_kb']} KB",
        "Camera": f"{e.get('Make', '')} {e.get('Model', '')}".strip() or "\u2014",
        "Date taken": str(e.get("DateTimeOriginal", "\u2014")),
        "Software": str(e.get("Software", "\u2014")),
        "GPS": f"{r['gps']['lat']}, {r['gps']['lon']}" if r["gps"] else "\u2014",
        "Risk level": r["risk"],
    }


def compare(path_a, path_b):
    """Compare two images: MD5 / SHA-1 / SHA-256, perceptual hash, and metadata differences."""
    ra, rb = analyze(path_a), analyze(path_b)
    ha, hb = ra["hashes"], rb["hashes"]
    exact = ha["sha256"] == hb["sha256"]
    out = {
        "md5_a": ha["md5"], "md5_b": hb["md5"],
        "sha1_a": ha["sha1"], "sha1_b": hb["sha1"],
        "sha256_a": ha["sha256"], "sha256_b": hb["sha256"],
        "hash_rows": [{"name": n, "a": ha[k], "b": hb[k], "same": ha[k] == hb[k]}
                      for n, k in (("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256"))],
        "exact_match": exact,
        "phash_a": None, "phash_b": None, "similarity": None,
        "verdict": "", "level": "bad", "error": None,
    }
    da, db = _details(ra), _details(rb)
    out["details"] = [{"label": k, "a": da[k], "b": db[k], "same": da[k] == db[k]} for k in da]
    if exact:
        out["verdict"], out["level"] = "IDENTICAL - files are byte-for-byte the same", "ok"
    try:
        pa, pb = perceptual_hash(path_a), perceptual_hash(path_b)
        dist = bin(int(pa, 16) ^ int(pb, 16)).count("1")
        out.update(phash_a=pa, phash_b=pb, similarity=round((64 - dist) / 64 * 100, 1))
        if not exact:
            if dist <= 10:
                out["verdict"], out["level"] = "SIMILAR - looks the same but the file was changed (resized, edited, re-saved)", "warn"
            else:
                out["verdict"] = "DIFFERENT - images are not the same"
    except Exception as e:
        out["error"] = f"Cannot compare visually: {e}"
        if not exact:
            out["verdict"] = "DIFFERENT - file hashes do not match"
    return out
