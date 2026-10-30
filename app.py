"""Web UI:  python app.py  ->  open http://127.0.0.1:5000"""
import base64
import io
import os
import tempfile
from flask import Flask, render_template, request
from PIL import Image, ImageOps
from analyzer import analyze, compare

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB limit


def thumb(path):
    """Small JPEG preview as a data URI (nothing is stored on the server)."""
    try:
        with Image.open(path) as im:
            im = ImageOps.exif_transpose(im).convert("RGB")
            im.thumbnail((480, 480))
            buf = io.BytesIO()
            im.save(buf, "JPEG", quality=80)
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None


def save_temp(f):
    fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(f.filename)[1].lower())
    os.close(fd)
    f.save(tmp)
    return tmp


@app.route("/", methods=["GET", "POST"])
def index():
    r = r_json = None
    f = request.files.get("image") if request.method == "POST" else None
    if f and f.filename:
        tmp = save_temp(f)
        try:
            r = analyze(tmp)
            r["file"] = os.path.basename(f.filename)
            r["preview"] = thumb(tmp)
        finally:
            os.remove(tmp)  # never keep uploads
        r_json = {k: v for k, v in r.items() if k != "preview"}
    return render_template("index.html", r=r, r_json=r_json, c=None, tab="analyze")


@app.route("/compare", methods=["POST"])
def compare_view():
    files = [request.files.get("image1"), request.files.get("image2")]
    tmps, comp = [], None
    try:
        if all(f and f.filename for f in files):
            for f in files:
                tmps.append(save_temp(f))
            comp = compare(*tmps)
            comp["name_a"], comp["name_b"] = (os.path.basename(f.filename) for f in files)
            comp["prev_a"], comp["prev_b"] = thumb(tmps[0]), thumb(tmps[1])
    finally:
        for t in tmps:
            os.remove(t)
    return render_template("index.html", r=None, r_json=None, c=comp, tab="compare")


if __name__ == "__main__":
    app.run(debug=True)
