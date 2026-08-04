# -*- coding: utf-8 -*-
"""
私人媒体站 —— 本地图片/视频上传与浏览
启动:  .venv/Scripts/python.exe app.py
访问:  http://127.0.0.1:8899
"""
import os
import uuid
import json
from functools import wraps

from flask import (Flask, request, redirect, url_for, render_template,
                   send_from_directory, session, flash, jsonify, abort)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = r"F:\media-site-uploads"
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 允许的扩展名（图片 + 视频）
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".avif", ".heic"}
VIDEO_EXTS = {".mp4", ".webm", ".mov", ".mkv", ".avi", ".flv", ".m4v", ".wmv", ".ts"}
ALLOWED_EXTS = IMAGE_EXTS | VIDEO_EXTS
MAX_FILE_MB = 2048  # 单文件最大 2GB


def load_accounts():
    """从 config.json 读取账号列表；不存在则生成默认配置。"""
    defaults = {
        "accounts": [
            {
                "username": "user",
                "email": "user@example.com",
                "password": "change-me"
            }
        ]
    }
    if not os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(defaults, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        return defaults["accounts"]
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        accounts = data.get("accounts", [])
        if isinstance(accounts, list) and accounts:
            return accounts
    except (OSError, ValueError):
        pass
    return defaults["accounts"]


ACCOUNTS = load_accounts()
app = Flask(__name__)
app.secret_key = os.environ.get("MEDIA_SITE_SECRET", uuid.uuid4().hex)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * 1024 * 1024


def check_login(identifier, password):
    """用户名 或 邮箱（任一匹配）+ 密码，全部通过才放行。"""
    identifier = (identifier or "").strip()
    if not identifier or not password:
        return False
    for acc in ACCOUNTS:
        user_match = acc.get("username", "").strip() == identifier
        email_match = acc.get("email", "").strip().lower() == identifier.lower()
        if (user_match or email_match) and acc.get("password", "") == password:
            return True
    return False


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # 预览模式（MEDIA_PREVIEW=1）仅用于本地截图查看页面效果，正常使用不受影响
        if os.environ.get("MEDIA_PREVIEW") == "1":
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


def sector_dir(sec):
    """四个独立板块各自的存储目录（互不干扰）。"""
    d = os.path.join(UPLOAD_DIR, f"sector{sec}")
    os.makedirs(d, exist_ok=True)
    return d


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
        identifier = request.form.get("identifier", "")
        pwd = request.form.get("password", "")
        if check_login(identifier, pwd):
            session["logged_in"] = True
            session["username"] = identifier.strip()
            return redirect(url_for("index"))
        flash("用户名/邮箱或密码不正确")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/sector/<int:n>")
@login_required
def sector(n):
    if n not in (1, 2, 3, 4):
        abort(404)
    return render_template("sector.html", n=n)


@app.route("/sector/<int:n>/inner")
@login_required
def sector_inner(n):
    if n not in (1, 2, 3, 4):
        abort(404)
    return render_template("sector_inner.html", n=n)


@app.route("/api/media")
@login_required
def api_media():
    sec = request.args.get("sec")
    sec = int(sec) if sec in ("1", "2", "3", "4") else None
    return jsonify({"ok": True, "items": list_media(sec)})


@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    sec = request.args.get("sec")
    sec = int(sec) if sec in ("1", "2", "3", "4") else None
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
            f.save(os.path.join(base, final))
            results.append({"name": final, "kind": kind})
        except Exception as e:
            errors.append(f"{base_name}: 保存失败 ({e})")

    return jsonify({"ok": True, "uploaded": results, "errors": errors})


@app.route("/api/delete", methods=["POST"])
@login_required
def api_delete():
    sec = request.args.get("sec")
    sec = int(sec) if sec in ("1", "2", "3", "4") else None
    base = sector_dir(sec) if sec else UPLOAD_DIR
    name = request.json.get("name", "") if request.is_json else request.form.get("name", "")
    name = os.path.basename(name)
    p = os.path.join(base, name)
    if not os.path.isfile(p):
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    try:
        os.remove(p)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/media/<path:name>")
@login_required
def media(name):
    sec = request.args.get("sec")
    sec = int(sec) if sec in ("1", "2", "3", "4") else None
    base = sector_dir(sec) if sec else UPLOAD_DIR
    name = os.path.basename(name)
    if not os.path.isfile(os.path.join(base, name)):
        abort(404)
    return send_from_directory(base, name, conditional=True)


if __name__ == "__main__":
    print("=" * 56)
    print("  私人媒体站已启动")
    print(f"  访问地址:  http://127.0.0.1:8899")
    print(f"  上传目录:  {UPLOAD_DIR}")
    print(f"  账号配置:  {CONFIG_PATH}")
    print(f"  已配置账号: {len(ACCOUNTS)} 个")
    print("  按 Ctrl+C 停止")
    print("=" * 56)
    app.run(host="127.0.0.1", port=8899, debug=False, threaded=True)
