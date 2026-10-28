import psycopg2
from psycopg2.extras import RealDictCursor
import os
import io
import uuid
import secrets
import time
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
)

LOGIN_ATTEMPTS = {}
DATABASE_URL = os.environ.get("DATABASE_URL")
VIEWER_PASSWORD = os.environ.get("VIEWER_PASSWORD")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")


# ---------------- CSRF PROTECTION ----------------

@app.before_request
def protect_post_requests():
    if request.method == "POST" and request.endpoint != "login":
        token = session.get("csrf_token")
        supplied = (
            request.form.get("csrf_token", "")
            or request.form.get("_csrf_token", "")
        )
        if not token or not secrets.compare_digest(token, supplied):
            return "Invalid or expired form token. Refresh the page and try again.", 400


@app.context_processor
def inject_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------- DATABASE ----------------

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing from environment variables.")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            caption TEXT NOT NULL,
            image BYTEA,
            mime_type TEXT,
            sort_order INTEGER
        )
    """)
    cur.execute("ALTER TABLE photos ADD COLUMN IF NOT EXISTS image BYTEA")
    cur.execute("ALTER TABLE photos ADD COLUMN IF NOT EXISTS mime_type TEXT")
    cur.execute("ALTER TABLE photos ADD COLUMN IF NOT EXISTS sort_order INTEGER")
    cur.execute("UPDATE photos SET sort_order = id WHERE sort_order IS NULL")

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
    cur.execute("ALTER TABLE settings ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 1")

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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id SERIAL PRIMARY KEY,
            event TEXT NOT NULL,
            role TEXT,
            user_agent TEXT,
            ip_address TEXT,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("ALTER TABLE login_history ADD COLUMN IF NOT EXISTS ip_address TEXT")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id SERIAL PRIMARY KEY,
            message TEXT NOT NULL,
            is_read BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id SERIAL PRIMARY KEY,
            token_hash TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


# ---------------- SETTINGS ----------------

def get_settings():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT heading, viewer_password, admin_password, session_version
        FROM settings
        WHERE id = 1
    """)
    settings = cur.fetchone()

    if not settings:
        settings = {
            "heading": "Meri Zindagi Hain Tu",
            "viewer_password": VIEWER_PASSWORD,
            "admin_password": ADMIN_PASSWORD,
            "session_version": 1,
        }

        cur.execute("""
            INSERT INTO settings
            (id, heading, viewer_password, admin_password, session_version)
            VALUES (1, %s, %s, %s, %s)
        """, (
            settings["heading"],
            settings["viewer_password"],
            settings["admin_password"],
            settings["session_version"],
        ))
        conn.commit()

    cur.close()
    conn.close()
    return settings


def save_settings(data):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE settings
        SET heading = %s,
            viewer_password = %s,
            admin_password = %s,
            session_version = %s
        WHERE id = 1
    """, (
        data["heading"],
        data["viewer_password"],
        data["admin_password"],
        data.get("session_version", 1),
    ))
    conn.commit()
    cur.close()
    conn.close()


# ---------------- EMAIL ----------------

def send_email(to_email, subject, body):
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_email = os.environ.get("SMTP_EMAIL")
    smtp_password = os.environ.get("SMTP_PASSWORD")

    if not all([smtp_host, smtp_email, smtp_password, to_email]):
        print("Email not sent: SMTP settings are incomplete.")
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_email
    message["To"] = to_email
    message.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.send_message(message)
        return True
    except Exception as exc:
        print("Email delivery failed:", type(exc).__name__)
        return False


def send_security_alert(subject, body):
    recipient = os.environ.get("ALERT_EMAIL") or os.environ.get("RECOVERY_EMAIL")
    if recipient:
        send_email(recipient, subject, body)


# ---------------- EVENT LOGGING ----------------

def get_client_ip():
    # Do not blindly trust arbitrary X-Forwarded-For headers.
    # REMOTE_ADDR may be the proxy address when hosted behind a proxy.
    return request.remote_addr or "Unknown"


def log_event(event, role=None):
    user_agent = request.headers.get("User-Agent", "Unknown")[:500]
    ip_address = get_client_ip()

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO login_history (event, role, user_agent, ip_address)
        VALUES (%s, %s, %s, %s)
    """, (event, role, user_agent, ip_address))

    cur.execute("""
        INSERT INTO notifications (message, is_read)
        VALUES (%s, FALSE)
    """, (f"{event} — {role or 'Unknown role'} — {ip_address}",))

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
    cur.close()
    conn.close()

    send_security_alert(
        f"RecallAlbum security alert: {event}",
        f"Event: {event}\nRole: {role or 'Unknown'}\n"
        f"IP address: {ip_address}\nBrowser/device: {user_agent}\n"
        f"Time: {datetime.utcnow().isoformat()} UTC",
    )


def get_login_history():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM login_history
        WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '3 days'
    """)
    cur.execute("""
        SELECT id, event, role, user_agent, ip_address, created_at
        FROM login_history
        ORDER BY created_at DESC
        LIMIT 100
    """)
    rows = cur.fetchall()
    conn.commit()
    cur.close()
    conn.close()
    return rows


def get_notifications():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM notifications
        WHERE is_read = TRUE
          AND created_at < CURRENT_TIMESTAMP - INTERVAL '2 days'
    """)
    cur.execute("""
        DELETE FROM notifications
        WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '30 days'
    """)
    cur.execute("""
        SELECT id, message, is_read, created_at
        FROM notifications
        ORDER BY created_at DESC
        LIMIT 100
    """)
    rows = cur.fetchall()
    conn.commit()
    cur.close()
    conn.close()
    return rows


# ---------------- PHOTOS / AUDIO ----------------

def get_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, url, caption, sort_order
        FROM photos
        ORDER BY COALESCE(sort_order, id), id
    """)
    photos = cur.fetchall()
    cur.close()
    conn.close()
    return photos


def get_audio():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, filename, mime_type
        FROM audio
        ORDER BY id DESC
        LIMIT 1
    """)
    audio = cur.fetchone()
    cur.close()
    conn.close()
    return audio


# ---------------- SESSION HELPERS ----------------

def create_session_record(role):
    session_id = secrets.token_urlsafe(32)
    session["session_id"] = session_id

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO active_sessions (session_id, role, user_agent)
        VALUES (%s, %s, %s)
    """, (
        session_id,
        role,
        request.headers.get("User-Agent", "Unknown")[:500],
    ))
    conn.commit()
    cur.close()
    conn.close()


def remove_current_session_record():
    session_id = session.get("session_id")
    if not session_id:
        return

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM active_sessions WHERE session_id = %s", (session_id,))
    conn.commit()
    cur.close()
    conn.close()


def check_session():
    role = session.get("role")
    session_id = session.get("session_id")

    if not role or not session_id:
        return False

    settings = get_settings()
    if session.get("session_version") != settings.get("session_version"):
        session.clear()
        return False

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id FROM active_sessions
        WHERE session_id = %s AND role = %s
    """, (session_id, role))
    active = cur.fetchone()

    if active:
        cur.execute("""
            UPDATE active_sessions
            SET last_seen = CURRENT_TIMESTAMP
            WHERE session_id = %s
        """, (session_id,))
        conn.commit()

    cur.close()
    conn.close()
    return active is not None


# ---------------- LOGIN ----------------

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip_address = get_client_ip()
        now = time.time()

        attempts = LOGIN_ATTEMPTS.get(ip_address, [])
        attempts = [t for t in attempts if now - t < 300]

        if len(attempts) >= 8:
            flash("Too many attempts. Please wait 5 minutes.")
            LOGIN_ATTEMPTS[ip_address] = attempts
            return render_template("index.html")

        LOGIN_ATTEMPTS[ip_address] = attempts

        password = request.form.get("password", "")
        settings = get_settings()

        if settings.get("admin_password") and secrets.compare_digest(
            password, settings["admin_password"]
        ):
            LOGIN_ATTEMPTS[ip_address] = []
            session.clear()
            session["role"] = "admin"
            session["session_version"] = settings.get("session_version", 1)
            create_session_record("admin")
            log_event("Successful login", "admin")
            return redirect(url_for("dashboard"))

        if settings.get("viewer_password") and secrets.compare_digest(
            password, settings["viewer_password"]
        ):
            LOGIN_ATTEMPTS[ip_address] = []
            session.clear()
            session["role"] = "viewer"
            session["session_version"] = settings.get("session_version", 1)
            create_session_record("viewer")
            log_event("Successful login", "viewer")
            return redirect(url_for("gallery"))

        attempts.append(now)
        LOGIN_ATTEMPTS[ip_address] = attempts
        log_event("Failed login", "unknown")
        flash("Wrong password, try again.")

    return render_template("index.html")


# ---------------- GALLERY ----------------

@app.route("/gallery")
def gallery():
    if not check_session():
        session.clear()
        return redirect(url_for("login"))

    photos = get_data()
    settings = get_settings()
    return render_template(
        "album.html",
        photos=photos,
        heading=settings["heading"],
    )


@app.route("/private_image/<int:photo_id>")
def private_image(photo_id):
    if not check_session():
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT image, mime_type
        FROM photos
        WHERE id = %s
    """, (photo_id,))
    photo = cur.fetchone()
    cur.close()
    conn.close()

    if not photo or not photo["image"]:
        return "Image not found", 404

    return send_file(
        io.BytesIO(bytes(photo["image"])),
        mimetype=photo["mime_type"] or "image/jpeg",
    )


@app.route("/private_audio")
def private_audio():
    if not check_session():
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT audio, mime_type, filename
        FROM audio
        ORDER BY id DESC
        LIMIT 1
    """)
    audio = cur.fetchone()
    cur.close()
    conn.close()

    if not audio:
        return "Audio not found", 404

    return send_file(
        io.BytesIO(bytes(audio["audio"])),
        mimetype=audio["mime_type"] or "audio/mpeg",
        download_name=audio["filename"],
    )


# ---------------- ADMIN DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    settings = get_settings()
    return render_template(
        "dashboard.html",
        photos=get_data(),
        settings=settings,
        active_sessions=get_active_sessions(),
        login_history=get_login_history(),
        notifications=get_notifications(),
    )


def get_active_sessions():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT role, user_agent, created_at, last_seen
        FROM active_sessions
        ORDER BY last_seen DESC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


# ---------------- PHOTO MANAGEMENT ----------------

@app.route("/add_photo", methods=["POST"])
def add_photo():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    image = request.files.get("image")
    caption = request.form.get("caption", "").strip()

    if not image or not image.filename or not caption:
        flash("Please choose an image and enter a caption.")
        return redirect(url_for("dashboard"))

    allowed_types = {
        "image/jpeg", "image/png", "image/webp", "image/gif"
    }
    mime_type = image.mimetype

    if mime_type not in allowed_types:
        flash("Only JPG, PNG, WEBP and GIF images are allowed.")
        return redirect(url_for("dashboard"))

    image_bytes = image.read()
    if not image_bytes:
        flash("The selected image is empty.")
        return redirect(url_for("dashboard"))

    filename = secure_filename(image.filename) or "photo"
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT COALESCE(MAX(sort_order), 0) + 1 AS next_order
        FROM photos
    """)
    next_order = cur.fetchone()["next_order"]

    cur.execute("""
        INSERT INTO photos (url, caption, image, mime_type, sort_order)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        filename,
        caption,
        psycopg2.Binary(image_bytes),
        mime_type,
        next_order,
    ))
    conn.commit()
    cur.close()
    conn.close()

    flash("Photo added.")
    return redirect(url_for("dashboard"))


@app.route("/edit_photo/<int:photo_id>", methods=["POST"])
def edit_photo(photo_id):
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    caption = request.form.get("caption", "").strip()

    try:
        sort_order = int(request.form.get("sort_order", "1"))
    except ValueError:
        flash("Invalid display order.")
        return redirect(url_for("dashboard"))

    if not caption or sort_order < 1:
        flash("Caption and a positive display order are required.")
        return redirect(url_for("dashboard"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE photos
        SET caption = %s, sort_order = %s
        WHERE id = %s
    """, (caption, sort_order, photo_id))
    conn.commit()
    cur.close()
    conn.close()

    flash("Photo updated.")
    return redirect(url_for("dashboard"))


@app.route("/delete_photo/<int:photo_id>", methods=["POST"])
def delete_photo(photo_id):
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM photos WHERE id = %s", (photo_id,))
    conn.commit()
    cur.close()
    conn.close()

    flash("Photo deleted.")
    return redirect(url_for("dashboard"))


@app.route("/add_audio", methods=["POST"])
def add_audio():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    audio = request.files.get("audio")
    if not audio or not audio.filename:
        flash("Choose an audio file first.")
        return redirect(url_for("dashboard"))

    audio_bytes = audio.read()
    if not audio_bytes:
        flash("The selected audio file is empty.")
        return redirect(url_for("dashboard"))

    filename = secure_filename(audio.filename) or "audio"
    mime_type = audio.mimetype or "audio/mpeg"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audio (filename, audio, mime_type)
        VALUES (%s, %s, %s)
    """, (filename, psycopg2.Binary(audio_bytes), mime_type))
    conn.commit()
    cur.close()
    conn.close()

    flash("Audio uploaded to the database.")
    return redirect(url_for("dashboard"))


# ---------------- SETTINGS UPDATE ----------------

@app.route("/update_settings", methods=["POST"])
def update_settings():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    settings = get_settings()
    old_viewer_password = settings.get("viewer_password")
    old_admin_password = settings.get("admin_password")

    heading = request.form.get("heading", settings["heading"]).strip()
    viewer_password = request.form.get("viewer_password", "")
    admin_password = request.form.get("admin_password", "")

    if not heading:
        heading = settings["heading"]

    # Empty values mean "keep current password".
    if viewer_password == "":
        viewer_password = old_viewer_password
    if admin_password == "":
        admin_password = old_admin_password

    if viewer_password is not None and len(viewer_password) < 4:
        flash("Viewer password must be at least 4 characters.")
        return redirect(url_for("dashboard"))

    if admin_password is not None and len(admin_password) < 4:
        flash("Admin password must be at least 4 characters.")
        return redirect(url_for("dashboard"))

    password_changed = (
        viewer_password != old_viewer_password
        or admin_password != old_admin_password
    )

    settings["heading"] = heading
    settings["viewer_password"] = viewer_password
    settings["admin_password"] = admin_password

    if password_changed:
        settings["session_version"] = int(settings.get("session_version") or 1) + 1

    save_settings(settings)

    if password_changed:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM active_sessions")
        conn.commit()
        cur.close()
        conn.close()
        log_event("Password changed", "admin")
        session.clear()
        flash("Passwords updated. Please log in again.")
        return redirect(url_for("login"))

    flash("Settings saved.")
    return redirect(url_for("dashboard"))


# ---------------- LOGIN HISTORY CONTROLS ----------------

@app.route("/delete_login_history/<int:history_id>", methods=["POST"])
def delete_login_history(history_id):
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM login_history WHERE id = %s", (history_id,))
    conn.commit()
    cur.close()
    conn.close()
    flash("Login history entry deleted.")
    return redirect(url_for("dashboard"))


@app.route("/clear_login_history", methods=["POST"])
def clear_login_history():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM login_history")
    conn.commit()
    cur.close()
    conn.close()
    flash("Login history cleared.")
    return redirect(url_for("dashboard"))


# ---------------- NOTIFICATION CONTROLS ----------------

@app.route("/mark_notifications_read", methods=["POST"])
def mark_notifications_read():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE notifications SET is_read = TRUE")
    conn.commit()
    cur.close()
    conn.close()

    flash("All notifications marked as read.")
    return redirect(url_for("dashboard"))


@app.route("/toggle_notification/<int:notification_id>", methods=["POST"])
def toggle_notification(notification_id):
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE notifications
        SET is_read = NOT is_read
        WHERE id = %s
    """, (notification_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/delete_notification/<int:notification_id>", methods=["POST"])
def delete_notification(notification_id):
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM notifications WHERE id = %s", (notification_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for("dashboard"))


# ---------------- PASSWORD RECOVERY ----------------

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        role = request.form.get("role", "admin")
        if role not in ("admin", "viewer"):
            role = "admin"

        recipient = os.environ.get("RECOVERY_EMAIL") or os.environ.get("ALERT_EMAIL")
        # Keep the response generic so the page doesn't reveal whether email is configured.
        if recipient:
            raw_token = secrets.token_urlsafe(32)
            token_hash = secrets.token_hex(32)
            # Store a one-way digest of the actual token.
            import hashlib
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO password_reset_tokens
                (token_hash, role, expires_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP + INTERVAL '20 minutes')
            """, (token_hash, role))
            conn.commit()
            cur.close()
            conn.close()

            link = url_for("reset_password", token=raw_token, _external=True)
            send_email(
                recipient,
                "RecallAlbum password recovery",
                f"A password reset was requested for the {role} account.\n\n"
                f"Open this one-time link within 20 minutes:\n{link}\n\n"
                "If you did not request this, ignore this email.",
            )

        return render_template(
            "forgot_password.html",
            message="If recovery email is configured, a recovery link has been sent.",
        )

    return render_template("forgot_password.html", message=None)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, role
        FROM password_reset_tokens
        WHERE token_hash = %s
          AND used = FALSE
          AND expires_at > CURRENT_TIMESTAMP
    """, (token_hash,))
    reset = cur.fetchone()
    cur.close()
    conn.close()

    if not reset:
        return render_template(
            "reset_password.html",
            error="This recovery link is invalid or expired.",
            token=token,
        ), 400

    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 4:
            error = "Password must be at least 4 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            settings = get_settings()
            settings[f"{reset['role']}_password"] = password
            settings["session_version"] = int(settings.get("session_version") or 1) + 1

            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                UPDATE settings
                SET viewer_password = %s,
                    admin_password = %s,
                    session_version = %s
                WHERE id = 1
            """, (
                settings["viewer_password"],
                settings["admin_password"],
                settings["session_version"],
            ))
            cur.execute("""
                UPDATE password_reset_tokens
                SET used = TRUE
                WHERE id = %s
            """, (reset["id"],))
            cur.execute("DELETE FROM active_sessions")
            conn.commit()
            cur.close()
            conn.close()

            log_event("Password changed via recovery", reset["role"])
            flash("Password reset successful. Please log in.")
            return redirect(url_for("login"))

    return render_template("reset_password.html", error=error, token=token)


# ---------------- LOGOUT ALL DEVICES ----------------

@app.route("/logout_all", methods=["POST"])
def logout_all():
    if not check_session() or session.get("role") != "admin":
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE settings
        SET session_version = session_version + 1
        WHERE id = 1
    """)
    cur.execute("DELETE FROM active_sessions")
    conn.commit()
    cur.close()
    conn.close()

    session.clear()
    return redirect(url_for("login"))


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    if "role" in session:
        log_event("Logout", session.get("role"))
        remove_current_session_record()

    session.clear()
    return redirect(url_for("login"))


# ---------------- START APP ----------------

init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000)),
    )
