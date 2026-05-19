from __future__ import annotations

import base64
import os
import sqlite3
import tempfile
import zipfile
import json
from datetime import datetime
from functools import wraps
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from PIL import Image
from rembg import remove
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

# Roboflow inference SDK untuk Money Detection
try:
    from inference_sdk import InferenceHTTPClient
except ImportError:
    InferenceHTTPClient = None

BASE_DIR = Path(__file__).resolve().parent
if load_dotenv:
    load_dotenv(BASE_DIR / ".env")
DB_PATH = BASE_DIR / "database" / "app.db"
PROCESSED_DIR = BASE_DIR / "uploads" / "processed"
NODE_MODULES_DIR = BASE_DIR / "node_modules"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
ANONYMOUS_USERNAME = "anonymous"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")


ICONS = {
    "upload": '<i class="bi bi-cloud-upload-fill" style="font-size: 24px;"></i>',
    "gallery": '<i class="bi bi-images" style="font-size: 24px;"></i>',
    "logout": '<i class="bi bi-box-arrow-right" style="font-size: 24px;"></i>',
    "login": '<i class="bi bi-box-arrow-in-right" style="font-size: 24px;"></i>',
    "eye": '<i class="bi bi-eye-fill" style="font-size: 14px;"></i>',
    "trash": '<i class="bi bi-trash-fill" style="font-size: 14px;"></i>',
    "download": '<i class="bi bi-download" style="font-size: 14px;"></i>',
    "anonymous": '<i class="bi bi-question-circle-fill" style="font-size: 14px;"></i>',
    "edit": '<i class="bi bi-pencil-square" style="font-size: 14px;"></i>',
    "money": '<i class="bi bi-cash-coin" style="font-size: 24px;"></i>',  # Gunakan emoji rupiah yang lebih jelas
}

# ============================================================================
# ROBOFLOW MONEY DETECTION CONFIGURATION
# ============================================================================
# API Configuration untuk integrasi Roboflow Inference SDK
# Dokumentasi: https://docs.roboflow.com/inference/hosted-api
# Model: Roboflow Universe - Indonesia Money (Rupiah) Detection Workflow
ROBOFLOW_API_KEY = os.environ.get("ROBOFLOW_API_KEY", "oPcq7KAwftvR1wpgWKsq")
ROBOFLOW_WORKSPACE = os.environ.get("ROBOFLOW_WORKSPACE", "trisna-almuti")
ROBOFLOW_WORKFLOW_ID = os.environ.get("ROBOFLOW_WORKFLOW_ID", "general-segmentation-api")
ROBOFLOW_WORKFLOW_CLASSES = os.environ.get("ROBOFLOW_WORKFLOW_CLASSES", "")
ROBOFLOW_MODEL_ID = os.environ.get("ROBOFLOW_MODEL_ID", "")
ROBOFLOW_API_URL = "https://serverless.roboflow.com"

# Konfigurasi deteksi uang (confidence threshold dan kategori)
MONEY_CONFIDENCE_THRESHOLD = 0.75  # Minimum confidence untuk mendeteksi uang
MONEY_CLASSES = {
    "seribu rupiah": "1000",
    "dua ribu rupiah": "2000",
    "lima ribu rupiah": "5000",
    "sepuluhribu rupiah": "10000",  # Note: tanpa spasi sesuai dataset
    "dua puluh ribu rupiah": "20000",
    "lima puluh ribu rupiah": "50000",
    "seratusribu rupiah": "100000",  # Note: tanpa spasi sesuai dataset
}

# Inisialisasi Roboflow client jika library tersedia
roboflow_client = None
if InferenceHTTPClient:
    try:
        roboflow_client = InferenceHTTPClient(
            api_url=ROBOFLOW_API_URL,
            api_key=ROBOFLOW_API_KEY,
        )
        print("[INFO] Roboflow client initialized successfully")
    except Exception as e:
        print(f"[WARNING] Roboflow client initialization failed: {e}")



def icon_svg(name: str) -> str:
    return ICONS.get(name, "")


def parse_workflow_classes(raw_value: str) -> list[str]:
    return [part.strip() for part in (raw_value or "").split(",") if part.strip()]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def init_db() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    cur = db.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            file_name TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'removebg',
            money_detected TEXT,
            money_confidence REAL,
            money_message TEXT,
            money_detections_json TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    # Lightweight migration for existing DBs
    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(images)").fetchall()}
    migrations = [
        ("kind", "TEXT NOT NULL DEFAULT 'removebg'"),
        ("money_detected", "TEXT"),
        ("money_confidence", "REAL"),
        ("money_message", "TEXT"),
        ("money_detections_json", "TEXT"),
    ]
    for col_name, col_def in migrations:
        if col_name not in existing_cols:
            cur.execute(f"ALTER TABLE images ADD COLUMN {col_name} {col_def}")

    seeds = [
        ("admin", "112233", "admin"),
        ("user", "user12345", "user"),
        (ANONYMOUS_USERNAME, "anonymous-disabled-123", "user"),
    ]
    for username, password, role in seeds:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )

    db.commit()
    db.close()


def get_anonymous_user_id() -> int:
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (ANONYMOUS_USERNAME,)).fetchone()
    if row:
        return row["id"]
    db.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (ANONYMOUS_USERNAME, generate_password_hash("anonymous-disabled-123"), "user"),
    )
    db.commit()
    return db.execute("SELECT id FROM users WHERE username = ?", (ANONYMOUS_USERNAME,)).fetchone()[
        "id"
    ]


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


def login_required_ajax(view_func):
    """Decorator untuk AJAX requests - return JSON error instead of redirect"""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return jsonify({"success": False, "error": "Unauthorized - please login"}), 401
        return view_func(*args, **kwargs)

    return wrapped


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def image_owned_or_admin(image_id: int, user: sqlite3.Row) -> sqlite3.Row | None:
    db = get_db()
    row = db.execute(
        """
        SELECT images.*, users.username
        FROM images
        JOIN users ON users.id = images.user_id
        WHERE images.id = ?
        """,
        (image_id,),
    ).fetchone()
    if row is None:
        return None
    if user["role"] == "admin" or row["user_id"] == user["id"]:
        return row
    return None


def accessible_images(image_ids: list[int], user: sqlite3.Row) -> list[sqlite3.Row]:
    if not image_ids:
        return []

    placeholders = ",".join("?" for _ in image_ids)
    params: list[int] = image_ids[:]

    where_owner = ""
    if user["role"] != "admin":
        where_owner = "AND images.user_id = ?"
        params.append(user["id"])

    rows = get_db().execute(
        f"""
        SELECT images.*, users.username AS owner
        FROM images
        JOIN users ON users.id = images.user_id
        WHERE images.id IN ({placeholders})
        {where_owner}
        """,
        params,
    ).fetchall()
    return rows


def nav_items_for() -> list[dict[str, str]]:
    user = current_user()
    if user:
        # Authenticated users see: Upload, Gallery, Cek Rupiah, Logout
        return [
            {"endpoint": "upload_page", "label": "Upload", "icon": "upload"},
            {"endpoint": "gallery_page", "label": "Gallery", "icon": "gallery"},
            {"endpoint": "money_detector_page", "label": "Cek Rupiah", "icon": "money"},
            {"endpoint": "logout", "label": "Logout", "icon": "logout"},
        ]
    else:
        # Unauthenticated users see: public features + Login
        return [
            {"endpoint": "upload_page", "label": "Upload", "icon": "upload"},
            {"endpoint": "money_detector_page", "label": "Cek Rupiah", "icon": "money"},
            {"endpoint": "login", "label": "Login", "icon": "login"},
        ]


@app.context_processor
def inject_globals():
    user = current_user()
    return {
        "active_user": user,
        "nav_items": nav_items_for(),
        "icon": icon_svg,
    }


def paginate_images(
    user: sqlite3.Row,
    q: str,
    date_filter: str,
    owner_filter: str,
    page: int,
    page_size: int,
):
    db = get_db()
    conditions = []
    params: list[str | int] = []

    if user["role"] != "admin":
        conditions.append("images.user_id = ?")
        params.append(user["id"])

    if q:
        conditions.append("(LOWER(images.original_name) LIKE ? OR LOWER(users.username) LIKE ?)")
        params.append(f"%{q}%")
        params.append(f"%{q}%")

    if date_filter:
        conditions.append("DATE(images.created_at) = ?")
        params.append(date_filter)

    if user["role"] == "admin" and owner_filter == ANONYMOUS_USERNAME:
        conditions.append("users.username = ?")
        params.append(ANONYMOUS_USERNAME)

    where_sql = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    total = db.execute(
        f"""
        SELECT COUNT(1) AS total
        FROM images
        JOIN users ON users.id = images.user_id
        {where_sql}
        """,
        params,
    ).fetchone()["total"]

    if total == 0:
        return [], 0, 1, 1

    total_pages = max(1, (total + page_size - 1) // page_size)
    current_page = min(max(1, page), total_pages)
    offset = (current_page - 1) * page_size

    rows = db.execute(
        f"""
        SELECT images.id, images.original_name, images.file_name, images.created_at,
               images.kind, images.money_detected, images.money_confidence, images.money_message,
               users.username AS owner
        FROM images
        JOIN users ON users.id = images.user_id
        {where_sql}
        ORDER BY images.created_at DESC
        LIMIT ? OFFSET ?
        """,
        [*params, page_size, offset],
    ).fetchall()
    return rows, total, total_pages, current_page


def paginate_users_admin(q: str, page: int, page_size: int):
    db = get_db()
    where_parts = ["role in ('admin', 'user')", "username != 'anonymous'"]
    params: list[str | int] = []

    if q:
        where_parts.append("LOWER(username) LIKE ?")
        params.append(f"%{q}%")

    where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    total = db.execute(f"SELECT COUNT(1) AS total FROM users {where_sql}", params).fetchone()[
        "total"
    ]

    if total == 0:
        return [], 0, 1, 1

    total_pages = max(1, (total + page_size - 1) // page_size)
    current_page = min(max(1, page), total_pages)
    offset = (current_page - 1) * page_size

    rows = db.execute(
        f"""
        SELECT id, username, role, created_at
        FROM users
        {where_sql}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        [*params, page_size, offset],
    ).fetchall()
    return rows, total, total_pages, current_page

@app.route("/vendor/<path:filename>")
def vendor(filename: str):
    return send_from_directory(NODE_MODULES_DIR, filename)


@app.route("/")
def home():
    return redirect(url_for("upload_page"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("upload_page"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if len(username) < 3:
            flash("Username minimal 3 karakter.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password minimal 6 karakter.", "danger")
            return render_template("register.html")

        if username == ANONYMOUS_USERNAME:
            flash("Username tidak boleh anonymous.", "danger")
            return render_template("register.html")

        db = get_db()
        exists = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("Username sudah digunakan.", "danger")
            return render_template("register.html")

        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), "user"),
        )
        db.commit()
        flash("Akun berhasil dibuat, silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("upload_page"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and user["username"] == ANONYMOUS_USERNAME:
            flash("Akun anonymous tidak bisa login.", "danger")
            return render_template("login.html")

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Login berhasil sebagai {user['role']}.", "success")
            return redirect(url_for("upload_page"))

        flash("Username atau password salah.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Berhasil logout.", "info")
    return redirect(url_for("login"))


@app.route("/upload")
def upload_page():
    return render_template("upload.html", page_title="RemBG | Upload")


@app.route("/process", methods=["POST"])
def process_image():
    user = current_user()
    files = [f for f in request.files.getlist("file") if f and f.filename]

    if not files:
        flash("Pilih file gambar dulu.", "danger")
        return redirect(url_for("upload_page"))

    owner_id = user["id"] if user else get_anonymous_user_id()
    db = get_db()
    processed_items: list[dict[str, str]] = []
    skipped = 0

    try:
        for file in files:
            if not allowed_file(file.filename):
                skipped += 1
                continue

            original_name = secure_filename(file.filename)
            input_image = Image.open(file.stream)
            output_image = remove(input_image, post_process_mask=True)

            out_name = f"{uuid4().hex}_rmbg.png"
            out_path = PROCESSED_DIR / out_name
            output_image.save(out_path, "PNG")

            db.execute(
                "INSERT INTO images (user_id, original_name, file_name, kind, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    owner_id,
                    original_name,
                    out_name,
                    "removebg",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            processed_items.append(
                {
                    "out_path": str(out_path),
                    "download_name": f"{Path(original_name).stem}_rmbg.png",
                }
            )

        db.commit()

        if not processed_items:
            flash("Tidak ada file valid. Gunakan png/jpg/jpeg/webp.", "danger")
            return redirect(url_for("upload_page"))

        if user is None:
            if len(processed_items) == 1:
                item = processed_items[0]
                return send_file(
                    item["out_path"],
                    mimetype="image/png",
                    as_attachment=True,
                    download_name=item["download_name"],
                )

            zip_buffer = BytesIO()
            used_names: dict[str, int] = {}
            with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                for item in processed_items:
                    base_name = item["download_name"]
                    counter = used_names.get(base_name, 0)
                    used_names[base_name] = counter + 1
                    arcname = base_name if counter == 0 else f"{Path(base_name).stem}_{counter}.png"
                    zf.write(item["out_path"], arcname=arcname)
            zip_buffer.seek(0)
            return send_file(
                zip_buffer,
                mimetype="application/zip",
                as_attachment=True,
                download_name=f"removebg_guest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
            )

        msg = f"{len(processed_items)} gambar berhasil dihapus background."
        if skipped > 0:
            msg += f" {skipped} file dilewati (format tidak didukung)."
        flash(msg, "success")
        return redirect(url_for("gallery_page"))
    except Exception as exc:
        flash(f"Gagal proses gambar: {exc}", "danger")
        return redirect(url_for("upload_page"))


@app.route("/gallery")
@login_required
def gallery_page():
    user = current_user()
    q = request.args.get("q", "").strip().lower()
    date_filter = request.args.get("date", "").strip()
    owner_filter = request.args.get("owner", "").strip().lower()

    images, image_total, image_total_pages, image_current_page = paginate_images(
        user,
        q,
        date_filter,
        owner_filter,
        page=1,
        page_size=8,
    )

    users = []
    user_total = 0
    user_total_pages = 1
    user_current_page = 1
    if user["role"] == "admin":
        users, user_total, user_total_pages, user_current_page = paginate_users_admin(
            "",
            page=1,
            page_size=5,
        )

    return render_template(
        "gallery.html",
        images=images,
        users=users,
        page_title="RemBG | Gallery",
        q=q,
        date_filter=date_filter,
        owner_filter=owner_filter,
        is_admin=user["role"] == "admin",
        anonymous_username=ANONYMOUS_USERNAME,
        image_total=image_total,
        image_total_pages=image_total_pages,
        image_current_page=image_current_page,
        user_total=user_total,
        user_total_pages=user_total_pages,
        user_current_page=user_current_page,
    )


@app.route("/images/<int:image_id>/view")
@login_required
def view_image(image_id: int):
    user = current_user()
    row = image_owned_or_admin(image_id, user)
    if row is None:
        flash("Gambar tidak ditemukan / akses ditolak.", "danger")
        return redirect(url_for("gallery_page"))

    return send_file(PROCESSED_DIR / row["file_name"], mimetype="image/png")


@app.route("/images/<int:image_id>/download")
@login_required
def download_image(image_id: int):
    user = current_user()
    row = image_owned_or_admin(image_id, user)
    if row is None:
        flash("Gambar tidak ditemukan / akses ditolak.", "danger")
        return redirect(url_for("gallery_page"))

    filename = f"{Path(row['original_name']).stem}_rmbg.png"
    return send_file(
        PROCESSED_DIR / row["file_name"],
        mimetype="image/png",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/images/<int:image_id>/delete", methods=["POST"])
@login_required
def delete_image(image_id: int):
    user = current_user()
    row = image_owned_or_admin(image_id, user)
    if row is None:
        flash("Gambar tidak ditemukan / akses ditolak.", "danger")
        return redirect(url_for("gallery_page"))

    file_path = PROCESSED_DIR / row["file_name"]
    if file_path.exists():
        file_path.unlink(missing_ok=True)

    db = get_db()
    db.execute("DELETE FROM images WHERE id = ?", (image_id,))
    db.commit()

    flash("Gambar berhasil dihapus.", "success")
    return redirect(url_for("gallery_page"))


@app.route("/images/bulk-delete", methods=["POST"])
@login_required
def bulk_delete_images():
    user = current_user()
    image_ids = [int(x) for x in request.form.getlist("image_ids") if x.isdigit()]
    rows = accessible_images(image_ids, user)

    if not rows:
        flash("Tidak ada gambar valid yang dipilih.", "danger")
        return redirect(url_for("gallery_page"))

    db = get_db()
    for row in rows:
        file_path = PROCESSED_DIR / row["file_name"]
        if file_path.exists():
            file_path.unlink(missing_ok=True)
        db.execute("DELETE FROM images WHERE id = ?", (row["id"],))
    db.commit()

    flash(f"{len(rows)} gambar berhasil dihapus.", "success")
    return redirect(url_for("gallery_page"))


@app.route("/images/bulk-download", methods=["POST"])
@login_required
def bulk_download_images():
    user = current_user()
    image_ids = [int(x) for x in request.form.getlist("image_ids") if x.isdigit()]
    rows = accessible_images(image_ids, user)

    if not rows:
        flash("Tidak ada gambar valid yang dipilih.", "danger")
        return redirect(url_for("gallery_page"))

    zip_buffer = BytesIO()
    used_names: dict[str, int] = {}

    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            source = PROCESSED_DIR / row["file_name"]
            if not source.exists():
                continue

            base_name = f"{Path(row['original_name']).stem}_rmbg.png"
            counter = used_names.get(base_name, 0)
            used_names[base_name] = counter + 1
            final_name = base_name if counter == 0 else f"{Path(base_name).stem}_{counter}.png"
            zf.write(source, arcname=final_name)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"removebg_selected_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
    )


@app.route("/api/gallery")
@login_required
def api_gallery():
    user = current_user()
    q = request.args.get("q", "").strip().lower()
    date_filter = request.args.get("date", "").strip()
    owner_filter = request.args.get("owner", "").strip().lower()
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=8, type=int)
    page_size = min(max(page_size, 1), 50)

    rows, total, total_pages, current_page = paginate_images(
        user,
        q,
        date_filter,
        owner_filter,
        page,
        page_size,
    )
    items = [
        {
            "id": row["id"],
            "original_name": row["original_name"],
            "created_at": row["created_at"],
            "owner": row["owner"],
            "is_anonymous": row["owner"] == ANONYMOUS_USERNAME,
            "view_url": url_for("view_image", image_id=row["id"]),
            "download_url": url_for("download_image", image_id=row["id"]),
            "delete_url": url_for("delete_image", image_id=row["id"]),
        }
        for row in rows
    ]
    return jsonify(
        {
            "items": items,
            "pagination": {
                "total": total,
                "total_pages": total_pages,
                "current_page": current_page,
                "page_size": page_size,
            },
        }
    )


@app.route("/api/users")
@login_required
def api_users():
    user = current_user()
    if user["role"] != "admin":
        return jsonify({"error": "Akses ditolak"}), 403

    q = request.args.get("q", "").strip().lower()
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=5, type=int)
    page_size = min(max(page_size, 1), 50)

    rows, total, total_pages, current_page = paginate_users_admin(q, page, page_size)
    items = [
        {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
    return jsonify(
        {
            "items": items,
            "pagination": {
                "total": total,
                "total_pages": total_pages,
                "current_page": current_page,
                "page_size": page_size,
            },
        }
    )


@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@login_required
def admin_update_user(user_id: int):
    admin = current_user()
    if admin["role"] != "admin":
        return jsonify({"error": "Akses ditolak"}), 403

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "").strip()

    if len(username) < 3:
        return jsonify({"error": "Username minimal 3 karakter."}), 400

    if username is not None and username == ANONYMOUS_USERNAME:
        return jsonify({"error": "Username ini tidak boleh dipakai."}), 400

    db = get_db()
    target = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()

    if not target or target["username"] == ANONYMOUS_USERNAME:
        return jsonify({"error": "User tidak valid."}), 404

    # if target["role"] == 'admin' and username != target["username"]:
    #     return jsonify({"error": "Role admin tidak dapat diubah."}), 400

    exists = db.execute(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        (username, user_id),
    ).fetchone()
    if exists:
        return jsonify({"error": "Username sudah digunakan."}), 400

    if password:
        if len(password) < 6:
            return jsonify({"error": "Password minimal 6 karakter."}), 400
        db.execute(
            "UPDATE users SET username = ?, password_hash = ? WHERE id = ?",
            (username, generate_password_hash(password), user_id),
        )
    else:
        db.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))

    db.commit()
    return jsonify({"ok": True, "message": "User berhasil diupdate."})


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_delete_user(user_id: int):
    admin = current_user()
    if admin["role"] != "admin":
        return jsonify({"error": "Akses ditolak"}), 403

    db = get_db()
    target = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target or target["role"] != "user" or target["username"] == ANONYMOUS_USERNAME:
        return jsonify({"error": "User tidak valid."}), 404

    images = db.execute("SELECT file_name FROM images WHERE user_id = ?", (user_id,)).fetchall()
    for row in images:
        file_path = PROCESSED_DIR / row["file_name"]
        if file_path.exists():
            file_path.unlink(missing_ok=True)

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"ok": True, "message": "User dan seluruh fotonya berhasil dihapus."})


# ============================================================================
# MONEY DETECTION ROUTES (DETEKSI UANG RUPIAH)
# ============================================================================

@app.route("/money-detector")
def money_detector_page():
    """
    Route untuk menampilkan halaman Money Detection (Deteksi Uang Rupiah).
    Publik - tidak perlu login.
    Menampilkan UI dengan video stream dari webcam dan real-time detection.
    """
    return render_template("money_detector.html", page_title="RemBG | Cek Rupiah")


@app.route("/process-money", methods=["POST"])
def process_money():
    """
    Route untuk memproses deteksi uang dari image base64.
    
    Request JSON:
        {
            "image_data": "data:image/jpeg;base64,..." (base64 encoded image)
        }
    
    Response JSON:
        {
            "success": true,
            "detections": [...],
            "detected_money": "20000",
            "confidence": 0.87,
            "message": "Terdeteksi: Dua Puluh Ribu Rupiah"
        }
    """
    try:
        # ====================================================================
        # 1. EXTRACT & VALIDATE REQUEST DATA
        # ====================================================================
        data = request.get_json()
        if not data or "image_data" not in data:
            return jsonify({"success": False, "error": "Missing image_data"}), 400

        image_data_str = data.get("image_data", "")

        # Parse base64 data
        if image_data_str.startswith("data:image"):
            image_data_str = image_data_str.split(",", 1)[1]

        # Decode base64
        try:
            image_bytes = base64.b64decode(image_data_str)
        except Exception as e:
            print(f"[ERROR] Base64 decode failed: {str(e)}")
            return jsonify({"success": False, "error": "Invalid base64 data"}), 400

        # ====================================================================
        # 2. CHECK ROBOFLOW CLIENT
        # ====================================================================
        if not roboflow_client:
            print("[WARNING] Roboflow client not available, using fallback response")
            # Fallback response untuk testing tanpa API key valid
            return jsonify({
                "success": True,
                "detections": [],
                "detected_money": None,
                "confidence": 0,
                "message": "Mode demo - Roboflow API tidak tersedia. Install inference-sdk dan set API key."
            })

        # ====================================================================
        # 3. SAVE TEMPORARY FILE & RUN INFERENCE
        # ====================================================================
        tmp_file_path = None
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_file:
                tmp_file.write(image_bytes)
                tmp_file_path = tmp_file.name

            if ROBOFLOW_MODEL_ID:
                print(f"[INFO] Running Roboflow model inference on {tmp_file_path}")
                result = roboflow_client.infer_from_api_v0(
                    tmp_file_path,
                    model_id=ROBOFLOW_MODEL_ID,
                )
            else:
                # Run Roboflow workflow inference
                print(f"[INFO] Running Roboflow workflow inference on {tmp_file_path}")

                workflow_parameters = {}
                workflow_classes = parse_workflow_classes(ROBOFLOW_WORKFLOW_CLASSES)
                # Some workflows (e.g. SAM/segmentation templates) require an explicit class list.
                # If the env var isn't set, default to our money class names when using a segmentation-like workflow.
                if not workflow_classes and any(
                    key in (ROBOFLOW_WORKFLOW_ID or "").lower() for key in ("segmentation", "sam")
                ):
                    workflow_classes = list(MONEY_CLASSES.keys())
                if workflow_classes:
                    workflow_parameters["classes"] = workflow_classes

                result = roboflow_client.run_workflow(
                    workspace_name=ROBOFLOW_WORKSPACE,
                    workflow_id=ROBOFLOW_WORKFLOW_ID,
                    images={"image": tmp_file_path},
                    parameters=workflow_parameters or None,
                )

            print(f"[DEBUG] Roboflow response: {result}")

        except Exception as e:
            print(f"[ERROR] Roboflow inference error: {str(e)}")
            return jsonify({
                "success": False,
                "error": f"Inference error: {str(e)}"
            }), 500
        finally:
            # Cleanup temporary file
            if tmp_file_path and Path(tmp_file_path).exists():
                Path(tmp_file_path).unlink(missing_ok=True)

        # ====================================================================
        # 4. PARSE ROBOFLOW RESPONSE
        # ====================================================================
        detections = []
        top_detection = None
        top_confidence = 0

        try:
            # The SDK returns a list of decoded workflow outputs.
            # Normalize to a dict-like object for parsing convenience.
            result_obj = result
            if isinstance(result, list):
                result_obj = result[0] if result else {}
            if not isinstance(result_obj, dict):
                print(
                    f"[WARNING] Unexpected workflow output type: {type(result_obj).__name__}. "
                    "Cannot parse predictions."
                )
                result_obj = {}

            # Extract predictions from response
            outputs = result_obj.get("outputs", [])
            predictions = []
            
            if outputs and isinstance(outputs, list) and len(outputs) > 0 and isinstance(outputs[0], dict):
                predictions = outputs[0].get("predictions", [])
            else:
                raw_predictions = result_obj.get("predictions", [])
                if isinstance(raw_predictions, dict):
                    predictions = raw_predictions.get("predictions", [])
                else:
                    predictions = raw_predictions

            if not isinstance(predictions, list):
                print(f"[WARNING] Unexpected predictions type: {type(predictions).__name__}. Defaulting to empty list.")
                predictions = []

            # Process each prediction
            for prediction in predictions:
                if not isinstance(prediction, dict):
                    continue
                class_name = prediction.get("class", "").lower()
                confidence = float(prediction.get("confidence", 0))

                if confidence >= MONEY_CONFIDENCE_THRESHOLD:
                    bbox = {
                        "x": int(prediction.get("x", 0)),
                        "y": int(prediction.get("y", 0)),
                        "width": int(prediction.get("width", 0)),
                        "height": int(prediction.get("height", 0)),
                    }

                    detection = {
                        "class": class_name,
                        "confidence": round(confidence, 2),
                        "bbox": bbox,
                    }
                    detections.append(detection)

                    if confidence > top_confidence:
                        top_confidence = confidence
                        top_detection = detection

        except Exception as e:
            print(f"[ERROR] Error parsing response: {str(e)}")
            return jsonify({
                "success": False,
                "error": f"Parse error: {str(e)}"
            }), 500

        # ====================================================================
        # 5. MAP DETECTED CLASS TO NOMINAL VALUE
        # ====================================================================
        detected_money = None
        message = "Tidak ada uang terdeteksi"

        if top_detection:
            detected_class = top_detection["class"].lower()
            for class_key, nominal in MONEY_CLASSES.items():
                if class_key.lower() in detected_class or detected_class in class_key.lower():
                    detected_money = nominal
                    money_name = class_key.replace("rupiah", "Rupiah").title()
                    message = f"Terdeteksi: {money_name}"
                    break

        # ====================================================================
        # 6. RETURN RESPONSE
        # ====================================================================
        save_to_gallery = bool(data.get("save_to_gallery")) if isinstance(data, dict) else False
        image_id = None
        if save_to_gallery:
            user = current_user()
            owner_id = user["id"] if user else get_anonymous_user_id()
            original_name = (data.get("original_name") or "money_check.jpg") if isinstance(data, dict) else "money_check.jpg"
            safe_original = secure_filename(str(original_name)) or "money_check.jpg"

            out_name = f"{uuid4().hex}_money.jpg"
            out_path = PROCESSED_DIR / out_name
            out_path.write_bytes(image_bytes)

            db = get_db()
            db.execute(
                """
                INSERT INTO images (
                    user_id, original_name, file_name, kind,
                    money_detected, money_confidence, money_message, money_detections_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    owner_id,
                    safe_original,
                    out_name,
                    "money",
                    detected_money,
                    float(top_confidence) if top_detection else 0.0,
                    message,
                    json.dumps(detections, ensure_ascii=False),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )
            db.commit()
            image_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

        return jsonify({
            "success": True,
            "detections": detections,
            "detected_money": detected_money,
            "confidence": round(top_confidence, 2) if top_detection else 0,
            "message": message,
            "saved_image_id": image_id,
        })

    except Exception as e:
        print(f"[ERROR] process_money error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500


# ============================================================================
# DEBUG TEST ROUTE - REMOVE IN PRODUCTION
# ============================================================================
@app.route("/test-process-money", methods=["POST"])
def test_process_money():
    """
    Test endpoint tanpa login requirement untuk debug
    """
    try:
        print("[DEBUG] test_process_money called")
        data = request.get_json()
        print(f"[DEBUG] Request data: {data}")
        
        if not data or "image_data" not in data:
            return jsonify({"success": False, "error": "Missing image_data"}), 400

        image_data_str = data.get("image_data", "")
        
        if image_data_str.startswith("data:image"):
            image_data_str = image_data_str.split(",", 1)[1]

        image_bytes = base64.b64decode(image_data_str)
        print(f"[DEBUG] Decoded {len(image_bytes)} bytes")
        
        # Demo response
        return jsonify({
            "success": True,
            "detections": [],
            "detected_money": None,
            "confidence": 0,
            "message": "Test endpoint working - no Roboflow"
        })
    except Exception as e:
        print(f"[ERROR] test_process_money error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5100)
