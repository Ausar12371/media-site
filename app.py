# -*- coding: utf-8 -*-
"""
私人媒体站 —— 本地图片/视频上传与浏览
启动:  .venv/Scripts/python.exe app.py
访问:  http://127.0.0.1:8899
"""
import os
import time
import json
import hmac
import secrets
import threading
from functools import wraps

from flask import (Flask, request, redirect, url_for, render_template,
                   send_from_directory, session, flash, get_flashed_messages,
                   jsonify, abort)
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 上传目录：可用环境变量 MEDIA_SITE_UPLOADS 覆盖（便于部署迁移）
UPLOAD_DIR = os.environ.get("MEDIA_SITE_UPLOADS") or r"F:\media-site-uploads"
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 服务端口与监听地址（双栈：IPv4 + IPv6）
PORT = 8899
HOST_V4 = "0.0.0.0"
HOST_V6 = "::"

# 允许的扩展名（图片 + 视频）
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".avif", ".heic"}
VIDEO_EXTS = {".mp4", ".webm", ".mov", ".mkv", ".avi", ".flv", ".m4v", ".wmv", ".ts"}
ALLOWED_EXTS = IMAGE_EXTS | VIDEO_EXTS
MAX_FILE_MB = 2048  # 单文件最大 2GB
VALID_SECTORS = (1, 2, 3, 4)  # 四个板块编号


def load_config():
    """读取 config.json；缺失字段自动生成并写回。返回 (accounts, guest_token, secret_key)。"""
    data = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
    changed = False
    accounts = data.get("accounts")
    if not isinstance(accounts, list) or not accounts:
        accounts = [{"username": "user", "email": "user@example.com", "password": "change-me"}]
        data["accounts"] = accounts
        changed = True
    token = data.get("guest_token")
    if not token or not isinstance(token, str):
        token = secrets.token_urlsafe(16)
        data["guest_token"] = token
        changed = True
    key = data.get("secret_key")
    if not key or not isinstance(key, str) or len(key) < 16:
        key = secrets.token_hex(32)
        data["secret_key"] = key
        changed = True
    if changed:
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
    return accounts, token, key


ACCOUNTS, GUEST_TOKEN, SECRET_KEY = load_config()
app = Flask(__name__)
app.secret_key = os.environ.get("MEDIA_SITE_SECRET") or SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024
# 会话 Cookie 安全属性：HttpOnly 防脚本读取；SameSite=Lax 防跨站 CSRF 提交
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# 反代（Nginx 等）后取真实客户端 IP，用于登录限流
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


# ===== 登录限流：每 IP 每 5 分钟最多 8 次失败（线程安全） =====
LOGIN_LIMIT = 8
LOGIN_WINDOW = 300  # 秒
_login_fails = {}  # {ip: [首次失败时间戳, 失败次数]}
_login_lock = threading.Lock()


def login_fail(ip):
    now = time.time()
    with _login_lock:
        rec = _login_fails.get(ip)
        if not rec or now - rec[0] > LOGIN_WINDOW:
            _login_fails[ip] = [now, 1]
        else:
            rec[1] += 1


def login_blocked(ip):
    with _login_lock:
        rec = _login_fails.get(ip)
        if not rec:
            return False
        now = time.time()
        if now - rec[0] > LOGIN_WINDOW:
            _login_fails.pop(ip, None)
            return False
        return rec[1] >= LOGIN_LIMIT


def login_reset(ip):
    with _login_lock:
        _login_fails.pop(ip, None)


@app.after_request
def security_headers(resp):
    """全站安全响应头：防 MIME 嗅探 / 点击劫持 / 泄露来源。"""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    # 静态资源（音乐/视频/图片）允许 Cloudflare 边缘缓存，减少隧道回源流量
    # （Werkzeug 静态响应默认 no-cache，需强制覆盖）
    if request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


def check_login(identifier, password):
    """用户名 或 邮箱（任一匹配）+ 密码，全部通过才放行。"""
    identifier = (identifier or "").strip()
    if not identifier or not password:
        return False
    for acc in ACCOUNTS:
        user_match = acc.get("username", "").strip() == identifier
        email_match = acc.get("email", "").strip().lower() == identifier.lower()
        pwd_ok = hmac.compare_digest(str(acc.get("password", "")), str(password))
        if (user_match or email_match) and pwd_ok:
            return True
    return False


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 预览模式（MEDIA_PREVIEW=1）仅用于本地截图查看页面效果，正常使用不受影响
        if os.environ.get("MEDIA_PREVIEW") == "1":
            return f(*args, **kwargs)
        # 访客（guest）只读：GET 页面/媒体全部放行；POST（上传/删除）仍须登录
        if session.get("guest") and request.method == "GET":
            return f(*args, **kwargs)
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "未登录"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def file_kind(name):
    ext = os.path.splitext(name)[1].lower()
    if ext in IMAGE_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    return None


# 常见图片格式文件头（宽松校验：只拦明显伪造，不误伤合法文件）
_IMAGE_MAGIC = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),
    ".bmp": (b"BM",),
}


def looks_like_image(ext, head):
    """校验常见图片文件头；未知/视频类型不做校验（宽松放行）。"""
    magics = _IMAGE_MAGIC.get(ext)
    if not magics:
        return True
    if ext == ".webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    return any(head.startswith(m) for m in magics)


def sector_dir(sec):
    """四个独立板块各自的存储目录（互不干扰）。"""
    d = os.path.join(UPLOAD_DIR, f"sector{sec}")
    os.makedirs(d, exist_ok=True)
    return d


def parse_sec(value):
    """把请求参数里的板块号（"1"~"4"）解析为 int；非法/缺失返回 None。"""
    return int(value) if value in ("1", "2", "3", "4") else None


def valid_sector(n):
    """板块号是否合法（1~4）。"""
    return n in VALID_SECTORS


def list_media(sec=None):
    items = []
    base = sector_dir(sec) if sec else UPLOAD_DIR
    for f in os.listdir(base):
        p = os.path.join(base, f)
        if not os.path.isfile(p):
            continue
        kind = file_kind(f)
        if not kind:
            continue
        try:
            size = os.path.getsize(p)
            mtime = os.path.getmtime(p)
        except OSError:
            continue
        items.append({"name": f, "kind": kind, "size": size, "mtime": mtime})
    # 最新的在前
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        get_flashed_messages()  # 清空历史 flash，只保留本次提示
        ip = request.remote_addr or "?"
        if login_blocked(ip):
            flash("尝试过于频繁，请 5 分钟后再试")
            return redirect(url_for("login"))
        identifier = request.form.get("identifier", "")
        pwd = request.form.get("password", "")
        if check_login(identifier, pwd):
            login_reset(ip)
            session["logged_in"] = True
            session["username"] = identifier.strip()
            return redirect(url_for("index"))
        login_fail(ip)
        flash("用户名/邮箱或密码不正确")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/guest/<token>")
def guest(token):
    """访客链接：token 正确则标记为访客（只读），跳转大厅。"""
    if hmac.compare_digest(token, GUEST_TOKEN):
        session["guest"] = True
        session.pop("logged_in", None)
        return redirect(url_for("index"))
    abort(404)


@app.route("/guest/enter", methods=["POST"])
def guest_enter():
    """登录页「访客登录」按钮：标记访客（只读）并进入大厅。"""
    session["guest"] = True
    session.pop("logged_in", None)
    return redirect(url_for("index"))


# ========== 页面路由 ==========

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/sector/<int:n>")
@login_required
def sector(n):
    if not valid_sector(n):
        abort(404)
    return render_template("sector.html", n=n)


@app.route("/sector/<int:n>/inner")
@login_required
def sector_inner(n):
    if not valid_sector(n):
        abort(404)
    return render_template("sector_inner.html", n=n)


@app.route("/sector/<int:n>/story")
@login_required
def sector_story(n):
    # 故事阅读页：仅 DREAM(1) 有「梦（上）」故事
    if n != 1:
        abort(404)
    return render_template("story.html", n=n)


# ========== 数据 API（JSON） ==========

@app.route("/api/media")
@login_required
def api_media():
    sec = parse_sec(request.args.get("sec"))
    return jsonify({"ok": True, "items": list_media(sec)})


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    sec = parse_sec(request.args.get("sec"))
    base = sector_dir(sec) if sec else UPLOAD_DIR
    files = request.files.getlist("files")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"ok": False, "error": "没有选择文件"}), 400

    results, errors = [], []
    for f in files:
        if not f or not f.filename:
            continue
        # 保留原始文件名；重名时自动加序号，绝不覆盖
        base_name = os.path.basename(f.filename.replace("\\", "/"))
        name, ext = os.path.splitext(base_name)
        kind = file_kind(base_name)
        if not kind:
            errors.append(f"{base_name}: 不支持的文件类型（仅图片/视频）")
            continue
        final = base_name
        i = 1
        while os.path.exists(os.path.join(base, final)):
            final = f"{name}({i}){ext}"
            i += 1
        try:
            # 图片文件头校验：拦截内容与扩展名明显不符的伪装文件
            head = f.stream.read(16)
            if not looks_like_image(ext, head):
                errors.append(f"{base_name}: 文件内容与扩展名不符")
                continue
            f.save(os.path.join(base, final))
            results.append({"name": final, "kind": kind})
        except Exception as e:
            errors.append(f"{base_name}: 保存失败 ({e})")

    return jsonify({"ok": True, "uploaded": results, "errors": errors})


@app.route("/api/delete", methods=["POST"])
@login_required
def api_delete():
    sec = parse_sec(request.args.get("sec"))
    base = sector_dir(sec) if sec else UPLOAD_DIR
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    name = os.path.basename(name or "")
    if not name:
        return jsonify({"ok": False, "error": "缺少文件名"}), 400
    p = os.path.join(base, name)
    if not os.path.isfile(p):
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    try:
        os.remove(p)
        return jsonify({"ok": True})
    except OSError:
        # 不返回具体错误（避免泄露服务器路径信息）
        return jsonify({"ok": False, "error": "删除失败"}), 500


# ========== 媒体文件（登录/访客只读） ==========

@app.route("/media/<path:name>")
@login_required
def media(name):
    sec = parse_sec(request.args.get("sec"))
    base = sector_dir(sec) if sec else UPLOAD_DIR
    name = os.path.basename(name)
    if not os.path.isfile(os.path.join(base, name)):
        abort(404)
    resp = send_from_directory(base, name, conditional=True)
    # SVG 可能内嵌脚本：CSP sandbox 沙箱化，阻止脚本执行（防存储型 XSS）
    if name.lower().endswith(".svg"):
        resp.headers["Content-Security-Policy"] = "sandbox"
    return resp


def print_banner():
    """启动横幅：展示访问地址与关键配置（访客 token 仅显示前 4 位防泄露）。"""
    print("=" * 56)
    print("  私人媒体站已启动")
    print(f"  访问地址:  http://127.0.0.1:{PORT}  (IPv4) / http://[IPv6]:{PORT} (IPv6)")
    print(f"  上传目录:  {UPLOAD_DIR}")
    print(f"  账号配置:  {CONFIG_PATH}")
    print(f"  已配置账号: {len(ACCOUNTS)} 个")
    print(f"  访客链接:   http://127.0.0.1:{PORT}/guest/{GUEST_TOKEN[:4]}…（完整 token 见 config.json）")
    print("  按 Ctrl+C 停止")
    print("=" * 56)


def run_dual_stack():
    """双栈监听：IPv4 (0.0.0.0) + IPv6 (::) 同端口，两个线程各绑一个地址族。"""
    threading.Thread(
        target=lambda: app.run(host=HOST_V4, port=PORT, debug=False, threaded=True),
        daemon=True,
    ).start()
    app.run(host=HOST_V6, port=PORT, debug=False, threaded=True)


if __name__ == "__main__":
    print_banner()
    run_dual_stack()
