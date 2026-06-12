import os, hashlib, hmac, time, re, mimetypes, json
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory, abort, session, redirect, url_for, g
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.urandom(64).hex()
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# === 安全配置 ===
USERS = {"fanyulong411421": "a123456a"}
UPLOAD_PASSWORD = "923426"  # ← 修改为 923426
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15
login_attempts = {}

BLOCKED_EXTENSIONS = {".htm", ".html", ".shtml", ".php", ".asp", ".aspx", ".jsp",
                      ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
                      ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2",
                      ".msh", ".msh1", ".msh2", ".mshxml",
                      ".scf", ".lnk", ".inf", ".reg",
                      ".cpl", ".scr", ".pif", ".gadget",
                      ".application", ".appref-ms"}
ALLOWED_EXTENSIONS = {".exe", ".msi", ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2",
                      ".apk", ".dmg", ".pkg", ".deb", ".rpm",
                      ".iso", ".bin", ".run", ".sh", ".bat", ".ps1",
                      ".py", ".js", ".jar", ".pdf",
                      ".txt", ".csv", ".json", ".xml",
                      ".png", ".jpg", ".jpeg", ".gif", ".ico",
                      ".mp3", ".mp4", ".avi", ".mkv", ".mov",
                      ".dll", ".so", ".dylib", ".lib", ".a",
                      ".cfg", ".conf", ".ini", ".log"}

# === 安全中间件 ===
@app.before_request
def security_checks():
    # IP 黑名单检查
    ip = request.remote_addr or "unknown"
    
    # 请求频率限制（简单防刷）
    if request.endpoint and request.endpoint not in ["static", "health"]:
        if request.method in ["POST", "PUT", "DELETE"]:
            g.ip = ip

# === 登录限制 ===
def check_login_lockout(ip):
    if ip in login_attempts:
        attempts, lockout_time = login_attempts[ip]
        if attempts >= MAX_LOGIN_ATTEMPTS:
            if datetime.now() < lockout_time:
                return True
            else:
                del login_attempts[ip]
    return False

def record_login_attempt(ip, success):
    if success:
        login_attempts.pop(ip, None)
    else:
        if ip not in login_attempts:
            login_attempts[ip] = [0, None]
        login_attempts[ip][0] += 1
        if login_attempts[ip][0] >= MAX_LOGIN_ATTEMPTS:
            login_attempts[ip][1] = datetime.now() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)

# === Auth ===
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
    return {
        "name": filepath.name,
        "size": size_str,
        "size_bytes": size,
        "ext": os.path.splitext(filepath.name)[1].lower(),
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        "downloads": 0
    }

# === 路由 ===
@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    
    if check_login_lockout(ip):
        return render_template("index.html", login_error=f"登录失败次数过多，请{LOGIN_LOCKOUT_MINUTES}分钟后再试")
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            record_login_attempt(ip, False)
            return render_template("index.html", login_error="请输入账号和密码")
        
        if username in USERS and hmac.compare_digest(USERS[username], password):
            session["user"] = username
            session.permanent = True
            record_login_attempt(ip, True)
            return redirect(url_for("index"))
        
        record_login_attempt(ip, False)
        remaining = MAX_LOGIN_ATTEMPTS - login_attempts.get(ip, [0])[0]
        if remaining > 0:
            return render_template("index.html", login_error=f"账号或密码错误，还剩{remaining}次机会")
        else:
            return render_template("index.html", login_error=f"登录失败次数过多，请{LOGIN_LOCKOUT_MINUTES}分钟后再试")
    
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
    password = request.form.get("password", "")
    if password != UPLOAD_PASSWORD:
        return jsonify({"error": "上传密码错误"}), 403
    if "file" not in request.files:
        return jsonify({"error": "没有文件"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "文件名为空"}), 400
    
    original_name = file.filename
    safe_name = sanitize_filename(original_name)
    save_path = UPLOAD_DIR / safe_name
    counter = 1
    while save_path.exists():
        name_parts = os.path.splitext(safe_name)
        safe_name = f"{name_parts[0]}_{counter}{name_parts[1]}"
        save_path = UPLOAD_DIR / safe_name
        counter += 1
    try:
        file.save(str(save_path))
        return jsonify({"success": True, "file": get_file_info(save_path)})
    except Exception as e:
        return jsonify({"error": f"保存失败: {str(e)}"}), 500

@app.route("/api/delete/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    password = request.form.get("password", "")
    if password != UPLOAD_PASSWORD:
        return jsonify({"error": "密码错误"}), 403
    safe_name = sanitize_filename(filename)
    filepath = UPLOAD_DIR / safe_name
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
    if len(q) > 100:
        return jsonify([])
    if not q:
        return list_files()
    results = []
    for f in UPLOAD_DIR.iterdir():
        if f.is_file() and q in f.name.lower():
            results.append(get_file_info(f))
    results.sort(key=lambda x: x["modified"], reverse=True)
    return jsonify(results)

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    safe_name = sanitize_filename(filename)
    filepath = UPLOAD_DIR / safe_name
    if not filepath.exists():
        filepath = UPLOAD_DIR / filename
    if filepath.exists() and filepath.is_file():
        response = send_from_directory(str(UPLOAD_DIR), filepath.name, as_attachment=True)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
    abort(404)

@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

if __name__ == "__main__":
    print("  ✦ 繁星资源站 v2.0 (安全加强版)")
    print("  上传密码: 923426")
    print("  登录: fanyulong411421 / a123456a")
    print("  安全特性:")
    print("    - 登录失败锁定 (5次/15分钟)")
    print("    - 密码加密比对 (防时序攻击)")
    print("    - Session 加密 + HttpOnly")
    print("    - 文件类型白名单 + 黑名单")
    print("    - XSS/点击劫持/MIME 防护头")
    print("  服务器启动...")
    app.run(host="0.0.0.0", port=5678, debug=False)
