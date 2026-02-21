from __future__ import annotations

import os
import sqlite3
import zipfile
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

BASE_DIR = Path(__file__).resolve().parent
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
    "eye": '<i class="bi bi-eye-fill" style="font-size: 14px;"></i>',
    "trash": '<i class="bi bi-trash-fill" style="font-size: 14px;"></i>',
    "download": '<i class="bi bi-download" style="font-size: 14px;"></i>',
    "anonymous": '<i class="bi bi-question-circle-fill" style="font-size: 14px;"></i>',
    "edit": '<i class="bi bi-pencil-square" style="font-size: 14px;"></i>',
}


def icon_svg(name: str) -> str:
    return ICONS.get(name, "")


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
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

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
    return [
        {"endpoint": "upload_page", "label": "Upload", "icon": "upload"},
        {"endpoint": "gallery_page", "label": "Gallery", "icon": "gallery"},
        {"endpoint": "logout", "label": "Logout", "icon": "logout"},
    ]


@app.context_processor
def inject_globals():
    user = current_user()
    return {
        "active_user": user,
        "nav_items": nav_items_for() if user else [],
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
                "INSERT INTO images (user_id, original_name, file_name, created_at) VALUES (?, ?, ?, ?)",
                (
                    owner_id,
                    original_name,
                    out_name,
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


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5100)
