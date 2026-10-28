import os
import io
import uuid
import time
import secrets
from datetime import datetime, timedelta
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# =====================================================
# APP CONFIGURATION
# =====================================================

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is missing. "
        "Set a strong random SECRET_KEY in Render."
    )

app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024  # 12 MB
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RENDER") == "true"
)

DATABASE_URL = os.environ.get("DATABASE_URL")
VIEWER_PASSWORD = os.environ.get("VIEWER_PASSWORD")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

ALLOWED_IMAGE_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif"
}

ALLOWED_AUDIO_TYPES = {
    "audio/mpeg",
    "audio/mp3",
    "audio/wav",
    "audio/ogg",
    "audio/mp4",
    "audio/x-wav"
}


# =====================================================
# DATABASE
# =====================================================

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is missing.")

    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )


def init_db():
    conn = get_db()

    try:
        with conn.cursor() as cur:

            cur.execute("""
                CREATE TABLE IF NOT EXISTS photos (
                    id SERIAL PRIMARY KEY,
                    url TEXT NOT NULL,
                    caption TEXT NOT NULL,
                    image BYTEA,
                    mime_type TEXT
                )
            """)

            cur.execute("""
                ALTER TABLE photos
                ADD COLUMN IF NOT EXISTS image BYTEA
            """)

            cur.execute("""
                ALTER TABLE photos
                ADD COLUMN IF NOT EXISTS mime_type TEXT
            """)

            cur.execute("""
                ALTER TABLE photos
                ADD COLUMN IF NOT EXISTS serial_no INTEGER
            """)

            cur.execute("""
                UPDATE photos
                SET serial_no = id
                WHERE serial_no IS NULL
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS audio (
                    id SERIAL PRIMARY KEY,
                    filename TEXT NOT NULL,
                    audio BYTEA NOT NULL,
                    mime_type TEXT NOT NULL
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY,
                    heading TEXT NOT NULL,
                    viewer_password TEXT,
                    admin_password TEXT,
                    session_version INTEGER DEFAULT 1
                )
            """)

            cur.execute("""
                ALTER TABLE settings
                ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 1
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    user_agent TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Persistent login/logout history
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_history (
                    id SERIAL PRIMARY KEY,
                    event TEXT NOT NULL,
                    role TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Persistent admin notifications
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id SERIAL PRIMARY KEY,
                    message TEXT NOT NULL,
                    category TEXT DEFAULT 'info',
                    is_read BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("""
                INSERT INTO settings
                    (id, heading, viewer_password, admin_password, session_version)
                VALUES (1, 'Meri Zindagi Hain Tu', %s, %s, 1)
                ON CONFLICT (id) DO NOTHING
            """, (VIEWER_PASSWORD, ADMIN_PASSWORD))

            # Keep old installations working: fill missing env passwords only.
            cur.execute("""
                UPDATE settings
                SET viewer_password = COALESCE(viewer_password, %s),
                    admin_password = COALESCE(admin_password, %s)
                WHERE id = 1
            """, (VIEWER_PASSWORD, ADMIN_PASSWORD))

            # Automatically prune old records.
            cur.execute("""
                DELETE FROM login_history
                WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '3 days'
            """)

            cur.execute("""
                DELETE FROM notifications
                WHERE is_read = TRUE
                  AND created_at < CURRENT_TIMESTAMP - INTERVAL '2 days'
            """)

            cur.execute("""
                DELETE FROM notifications
                WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '30 days'
            """)

        conn.commit()

    finally:
        conn.close()


# =====================================================
# CSRF PROTECTION
# =====================================================

@app.before_request
def csrf_protection():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)

    if request.method == "POST":
        submitted = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")

        if not submitted or not secrets.compare_digest(
            submitted, expected
        ):
            abort(400, description="Invalid or missing CSRF token.")


@app.context_processor
def inject_csrf_token():
    return {
        "csrf_token": lambda: session.get("_csrf_token", "")
    }


# =====================================================
# RESPONSE SECURITY
# =====================================================

@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# =====================================================
# DATABASE HELPERS
# =====================================================

def get_settings():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT heading, viewer_password, admin_password,
                       session_version
                FROM settings
                WHERE id = 1
            """)
            settings = cur.fetchone()

        return settings

    finally:
        conn.close()


def get_data():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, url, caption, serial_no
                FROM photos
                ORDER BY serial_no ASC, id ASC
            """)
            return cur.fetchall()

    finally:
        conn.close()


def record_notification(message, category="info"):
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO notifications (message, category)
                VALUES (%s, %s)
            """, (message, category))

        conn.commit()

    finally:
        conn.close()


def record_history(event, role=None, user_agent=None):
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO login_history (event, role, user_agent)
                VALUES (%s, %s, %s)
            """, (event, role, user_agent))

            cur.execute("""
                DELETE FROM login_history
                WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '3 days'
            """)

        conn.commit()

    finally:
        conn.close()


# =====================================================
# SESSION MANAGEMENT
# =====================================================

def create_session_record(role):
    session_id = str(uuid.uuid4())
    user_agent = request.headers.get("User-Agent", "Unknown")

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO active_sessions
                    (session_id, role, user_agent)
                VALUES (%s, %s, %s)
            """, (session_id, role, user_agent))

        conn.commit()

    finally:
        conn.close()

    session["session_id"] = session_id


def remove_current_session_record():
    session_id = session.get("session_id")

    if not session_id:
        return

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT role, user_agent
                FROM active_sessions
                WHERE session_id = %s
            """, (session_id,))
            current = cur.fetchone()

            if current:
                cur.execute("""
                    INSERT INTO login_history
                        (event, role, user_agent)
                    VALUES ('logout', %s, %s)
                """, (current["role"], current["user_agent"]))

            cur.execute("""
                DELETE FROM active_sessions
                WHERE session_id = %s
            """, (session_id,))

            cur.execute("""
                DELETE FROM login_history
                WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '3 days'
            """)

        conn.commit()

    finally:
        conn.close()


def get_active_sessions():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM active_sessions
                WHERE last_seen < CURRENT_TIMESTAMP - INTERVAL '30 minutes'
            """)

            cur.execute("""
                SELECT id, session_id, role, user_agent,
                       created_at, last_seen
                FROM active_sessions
                ORDER BY last_seen DESC
            """)

            sessions = cur.fetchall()

        conn.commit()
        return sessions

    finally:
        conn.close()


def check_session():
    if "role" not in session:
        return False

    settings = get_settings()

    if not settings:
        session.clear()
        return False

    if session.get("session_version") != settings["session_version"]:
        remove_current_session_record()
        session.clear()
        return False

    session_id = session.get("session_id")

    if not session_id:
        session.clear()
        return False

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE active_sessions
                SET last_seen = CURRENT_TIMESTAMP
                WHERE session_id = %s
                RETURNING id
            """, (session_id,))

            found = cur.fetchone()

        conn.commit()

    finally:
        conn.close()

    if not found:
        session.clear()
        return False

    return True


def admin_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not check_session() or session.get("role") != "admin":
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    return wrapped


# =====================================================
# LOGIN RATE LIMIT
# =====================================================

_login_attempts = {}


def login_blocked():
    ip = request.remote_addr or "unknown"
    attempts = _login_attempts.get(ip, [])
    now = time.time()

    attempts = [t for t in attempts if now - t < 300]
    _login_attempts[ip] = attempts

    return len(attempts) >= 8


def register_failed_login():
    ip = request.remote_addr or "unknown"
    now = time.time()

    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < 300]
    attempts.append(now)

    _login_attempts[ip] = attempts


def clear_failed_logins():
    ip = request.remote_addr or "unknown"
    _login_attempts.pop(ip, None)


# =====================================================
# LOGIN
# =====================================================

@app.route("/", methods=["GET", "POST"])
def login():
    if "role" in session and check_session():
        if session["role"] == "admin":
            return redirect(url_for("dashboard"))
        return redirect(url_for("gallery"))

    error = None

    if request.method == "POST":
        if login_blocked():
            error = "Too many attempts. Please wait five minutes."
            return render_template("index.html", error=error), 429

        password = request.form.get("password", "")
        settings = get_settings()

        viewer_password = settings.get("viewer_password") if settings else None
        admin_password = settings.get("admin_password") if settings else None

        if viewer_password and secrets.compare_digest(
            password, str(viewer_password)
        ):
            role = "viewer"

        elif admin_password and secrets.compare_digest(
            password, str(admin_password)
        ):
            role = "admin"

        else:
            register_failed_login()
            record_history(
                "failed_login",
                None,
                request.headers.get("User-Agent", "Unknown")
            )
            record_notification("A failed login attempt occurred.", "security")
            error = "Wrong password, try again."
            return render_template("index.html", error=error), 401

        clear_failed_logins()
        session.clear()
        session["_csrf_token"] = secrets.token_urlsafe(32)
        session["role"] = role
        session["session_version"] = settings["session_version"]

        create_session_record(role)
        record_history(
            "login",
            role,
            request.headers.get("User-Agent", "Unknown")
        )
        record_notification(f"{role.title()} login successful.", "security")

        if role == "admin":
            return redirect(url_for("dashboard"))

        return redirect(url_for("gallery"))

    return render_template("index.html", error=error)


# =====================================================
# GALLERY
# =====================================================

@app.route("/gallery")
def gallery():
    if not check_session():
        return redirect(url_for("login"))

    settings = get_settings()

    return render_template(
        "album.html",
        photos=get_data(),
        heading=settings["heading"]
    )


# =====================================================
# PRIVATE IMAGE
# =====================================================

@app.route("/private_image/<int:photo_id>")
def private_image(photo_id):
    if not check_session():
        return redirect(url_for("login"))

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT image, mime_type
                FROM photos
                WHERE id = %s
            """, (photo_id,))
            photo = cur.fetchone()

        if not photo or not photo["image"]:
            abort(404)

        return send_file(
            io.BytesIO(bytes(photo["image"])),
            mimetype=photo["mime_type"] or "application/octet-stream"
        )

    finally:
        conn.close()


# =====================================================
# PRIVATE AUDIO ROUTE (KEPT FOR COMPATIBILITY)
# =====================================================

@app.route("/private_audio")
def private_audio():
    if not check_session():
        return redirect(url_for("login"))

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT audio, mime_type
                FROM audio
                ORDER BY id DESC
                LIMIT 1
            """)
            audio = cur.fetchone()

        if not audio or not audio["audio"]:
            abort(404)

        return send_file(
            io.BytesIO(bytes(audio["audio"])),
            mimetype=audio["mime_type"] or "audio/mpeg"
        )

    finally:
        conn.close()


# =====================================================
# ADMIN DASHBOARD
# =====================================================

@app.route("/dashboard")
@admin_required
def dashboard():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, event, role, user_agent, created_at
                FROM login_history
                WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '3 days'
                ORDER BY created_at DESC
                LIMIT 200
            """)
            login_history = cur.fetchall()

            cur.execute("""
                SELECT id, message, category, is_read, created_at
                FROM notifications
                ORDER BY created_at DESC
                LIMIT 100
            """)
            notifications = cur.fetchall()

            cur.execute("""
                SELECT COUNT(*) AS count
                FROM notifications
                WHERE is_read = FALSE
            """)
            unread = cur.fetchone()["count"]

        conn.commit()

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        photos=get_data(),
        settings=get_settings(),
        active_sessions=get_active_sessions(),
        login_history=login_history,
        notifications=notifications,
        unread_notifications=unread
    )


# =====================================================
# ADD PHOTO
# =====================================================

@app.route("/add_photo", methods=["POST"])
@admin_required
def add_photo():
    file = request.files.get("image")
    caption = request.form.get("caption", "").strip()

    if not file or not file.filename:
        flash("Please select an image.")
        return redirect(url_for("dashboard"))

    if not caption:
        flash("Please enter a caption.")
        return redirect(url_for("dashboard"))

    if file.mimetype not in ALLOWED_IMAGE_TYPES:
        flash("Use a JPG, PNG, WEBP, or GIF image.")
        return redirect(url_for("dashboard"))

    image_data = file.read()

    if not image_data or len(image_data) > 10 * 1024 * 1024:
        flash("Image must be smaller than 10 MB.")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename) or "photo"
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COALESCE(MAX(serial_no), 0) + 1 AS next_serial
                FROM photos
            """)
            serial_no = cur.fetchone()["next_serial"]

            cur.execute("""
                INSERT INTO photos
                    (url, caption, image, mime_type, serial_no)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                filename,
                caption,
                psycopg2.Binary(image_data),
                file.mimetype,
                serial_no
            ))

        conn.commit()

    finally:
        conn.close()

    record_notification("A new photo was added.", "album")
    flash("Photo added successfully.")
    return redirect(url_for("dashboard"))


# =====================================================
# EDIT PHOTO CAPTION AND SERIAL NUMBER
# =====================================================

@app.route("/edit_photo/<int:photo_id>", methods=["POST"])
@admin_required
def edit_photo(photo_id):
    caption = request.form.get("caption", "").strip()
    serial_text = request.form.get("serial_no", "").strip()

    if not caption:
        flash("Caption cannot be empty.")
        return redirect(url_for("dashboard"))

    try:
        serial_no = int(serial_text)
        if serial_no < 1:
            raise ValueError
    except ValueError:
        flash("Serial number must be a positive number.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE photos
                SET caption = %s, serial_no = %s
                WHERE id = %s
            """, (caption, serial_no, photo_id))

            if cur.rowcount == 0:
                flash("Photo not found.")
                return redirect(url_for("dashboard"))

        conn.commit()

    finally:
        conn.close()

    record_notification("A photo caption or order was changed.", "album")
    flash("Photo updated.")
    return redirect(url_for("dashboard"))


# =====================================================
# ADD / REPLACE AUDIO
# =====================================================

@app.route("/add_audio", methods=["POST"])
@admin_required
def add_audio():
    file = request.files.get("audio")

    if not file or not file.filename:
        flash("Please select an audio file.")
        return redirect(url_for("dashboard"))

    if file.mimetype not in ALLOWED_AUDIO_TYPES:
        flash("Select a supported audio file.")
        return redirect(url_for("dashboard"))

    audio_data = file.read()

    if not audio_data or len(audio_data) > 10 * 1024 * 1024:
        flash("Audio must be smaller than 10 MB.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM audio")
            cur.execute("""
                INSERT INTO audio (filename, audio, mime_type)
                VALUES (%s, %s, %s)
            """, (
                secure_filename(file.filename) or "audio",
                psycopg2.Binary(audio_data),
                file.mimetype
            ))

        conn.commit()

    finally:
        conn.close()

    flash("Audio uploaded.")
    return redirect(url_for("dashboard"))


# =====================================================
# DELETE PHOTO (POST ONLY)
# =====================================================

@app.route("/delete_photo/<int:photo_id>", methods=["POST"])
@admin_required
def delete_photo(photo_id):
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM photos WHERE id = %s", (photo_id,))
            deleted = cur.rowcount

        conn.commit()

    finally:
        conn.close()

    if deleted:
        record_notification("A photo was deleted.", "album")
        flash("Photo deleted.")
    else:
        flash("Photo not found.")

    return redirect(url_for("dashboard"))


# =====================================================
# UPDATE SETTINGS
# =====================================================

@app.route("/update_settings", methods=["POST"])
@admin_required
def update_settings():
    heading = request.form.get("heading", "").strip()
    new_viewer_password = request.form.get("viewer_password", "").strip()
    new_admin_password = request.form.get("admin_password", "").strip()

    if not heading:
        flash("Heading cannot be empty.")
        return redirect(url_for("dashboard"))

    if new_viewer_password and len(new_viewer_password) < 8:
        flash("Viewer password must be at least 8 characters.")
        return redirect(url_for("dashboard"))

    if new_admin_password and len(new_admin_password) < 12:
        flash("Admin password must be at least 12 characters.")
        return redirect(url_for("dashboard"))

    conn = get_db()

    try:
        with conn.cursor() as cur:
            if new_viewer_password or new_admin_password:
                cur.execute("""
                    UPDATE settings
                    SET heading = %s,
                        viewer_password = COALESCE(NULLIF(%s, ''), viewer_password),
                        admin_password = COALESCE(NULLIF(%s, ''), admin_password),
                        session_version = session_version + 1
                    WHERE id = 1
                """, (heading, new_viewer_password, new_admin_password))
            else:
                cur.execute("""
                    UPDATE settings
                    SET heading = %s
                    WHERE id = 1
                """, (heading,))

        conn.commit()

    finally:
        conn.close()

    record_notification("General settings were updated.", "security")
    flash("Settings updated. Password changes require logging in again.")
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# MARK NOTIFICATIONS READ
# =====================================================

@app.route("/mark_notifications_read", methods=["POST"])
@admin_required
def mark_notifications_read():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE notifications
                SET is_read = TRUE
                WHERE is_read = FALSE
            """)

            cur.execute("""
                DELETE FROM notifications
                WHERE is_read = TRUE
                  AND created_at < CURRENT_TIMESTAMP - INTERVAL '2 days'
            """)

        conn.commit()

    finally:
        conn.close()

    flash("Notifications marked as read.")
    return redirect(url_for("dashboard"))


# =====================================================
# LOG OUT ALL DEVICES
# =====================================================

@app.route("/logout_all", methods=["POST"])
@admin_required
def logout_all():
    conn = get_db()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE settings
                SET session_version = session_version + 1
                WHERE id = 1
            """)
            cur.execute("DELETE FROM active_sessions")

        conn.commit()

    finally:
        conn.close()

    record_notification("All active sessions were invalidated.", "security")
    record_history(
        "logout_all",
        "admin",
        request.headers.get("User-Agent", "Unknown")
    )
    session.clear()
    return redirect(url_for("login"))


# =====================================================
# LOG OUT
# =====================================================

@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "role" in session:
        remove_current_session_record()

    session.clear()
    return redirect(url_for("login"))


# =====================================================
# ERROR HANDLERS
# =====================================================

@app.errorhandler(413)
def too_large(_error):
    return "Upload too large. Maximum request size is 12 MB.", 413


@app.errorhandler(400)
def bad_request(error):
    return (
        "Bad request. Refresh the page and try again. "
        "If the issue continues, check that the form includes its CSRF token.",
        400
    )


# =====================================================
# START APP
# =====================================================

init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
