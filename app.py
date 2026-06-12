import os, hashlib, json
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, abort, session, redirect, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

USERS = {"fanyulong411421": "a123456a"}
UPLOAD_PASSWORD = "923426"
BLOCKED_EXTENSIONS = {".htm", ".html", ".shtml", ".php", ".asp", ".aspx", ".jsp",
                      ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
                      ".scf", ".lnk", ".inf", ".reg", ".cpl", ".scr", ".pif",
                      ".application", ".appref-ms"}
ALLOWED_EXTENSIONS = {".exe", ".msi", ".zip", ".rar", ".7z", ".gz", ".tar",
                      ".apk", ".dmg", ".pkg", ".deb", ".rpm", ".iso", ".bin",
                      ".pdf", ".txt", ".csv", ".json", ".xml", ".py", ".jar",
                      ".png", ".jpg", ".jpeg", ".gif", ".ico", ".dll", ".sh",
                      ".bat", ".ps1", ".run", ".mp3", ".mp4", ".avi", ".mov"}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in BLOCKED_EXTENSIONS: return False
    if ext in ALLOWED_EXTENSIONS: return True
    return True

def sanitize_filename(filename):
    name = secure_filename(filename)
    if not name:
        ext = os.path.splitext(filename)[1]
        name = hashlib.md5(filename.encode()).hexdigest()[:16] + ext
    return name

def get_file_info(filepath):
    stat = filepath.stat()
    size = stat.st_size
    if size < 1024: size_str = f"{size} B"
    elif size < 1024**2: size_str = f"{size/1024:.1f} KB"
    elif size < 1024**3: size_str = f"{size/(1024**2):.1f} MB"
    else: size_str = f"{size/(1024**3):.2f} GB"
    return {"name": filepath.name, "size": size_str, "size_bytes": size,
            "ext": os.path.splitext(filepath.name)[1].lower(),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and USERS[username] == password:
            session["user"] = username
            return redirect(url_for("index"))
        return render_template("index.html", login_error="账号或密码错误")
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html", logged_in=True, user=session.get("user", ""))

@app.route("/api/files")
@login_required
def list_files():
    files = []
    for f in sorted(UPLOAD_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file():
            files.append(get_file_info(f))
    return jsonify(files)

@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    if request.form.get("password", "") != UPLOAD_PASSWORD:
        return jsonify({"error": "上传密码错误"}), 403
    if "file" not in request.files:
        return jsonify({"error": "没有文件"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "文件名为空"}), 400
    safe_name = sanitize_filename(file.filename)
    save_path = UPLOAD_DIR / safe_name
    counter = 1
    while save_path.exists():
        parts = os.path.splitext(safe_name)
        safe_name = f"{parts[0]}_{counter}{parts[1]}"
        save_path = UPLOAD_DIR / safe_name
        counter += 1
    file.save(str(save_path))
    return jsonify({"success": True, "file": get_file_info(save_path)})

@app.route("/api/delete/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    if request.form.get("password", "") != UPLOAD_PASSWORD:
        return jsonify({"error": "密码错误"}), 403
    filepath = UPLOAD_DIR / sanitize_filename(filename)
    if not filepath.exists():
        filepath = UPLOAD_DIR / filename
    if filepath.exists() and filepath.is_file():
        filepath.unlink()
        return jsonify({"success": True})
    return jsonify({"error": "文件不存在"}), 404

@app.route("/api/search")
@login_required
def search_files():
    q = request.args.get("q", "").lower().strip()
    if not q: return list_files()
    results = []
    for f in UPLOAD_DIR.iterdir():
        if f.is_file() and q in f.name.lower():
            results.append(get_file_info(f))
    results.sort(key=lambda x: x["modified"], reverse=True)
    return jsonify(results)

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    filepath = UPLOAD_DIR / sanitize_filename(filename)
    if not filepath.exists():
        filepath = UPLOAD_DIR / filename
    if filepath.exists() and filepath.is_file():
        response = send_from_directory(str(UPLOAD_DIR), filepath.name, as_attachment=True)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    abort(404)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5678)), debug=False)
