import psycopg2
from psycopg2.extras import RealDictCursor
import os
import io
import uuid
import secrets
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
)
LOGIN_ATTEMPTS = {}

@app.before_request
def protect_post_requests():
    if request.method == "POST" and request.endpoint != "login":
        token = session.get("csrf_token")
        supplied = request.form.get("csrf_token", "") or request.form.get("_csrf_token", "")
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

DATABASE_URL = os.environ.get('DATABASE_URL')


def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor
    )


# ---------------- DATABASE SETUP ----------------

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

    cur.execute("""
        ALTER TABLE photos
        ADD COLUMN IF NOT EXISTS image BYTEA
    """)
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
        ALTER TABLE photos
        ADD COLUMN IF NOT EXISTS mime_type TEXT
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            heading TEXT NOT NULL,
            viewer_password TEXT,
            admin_password TEXT
        )
    """)

    cur.execute("""
        ALTER TABLE settings
        ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 1
    """)

    # Active login sessions
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

    cur.execute("""CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY, event TEXT NOT NULL, role TEXT, user_agent TEXT,
        ip_address TEXT, created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("ALTER TABLE login_history ADD COLUMN IF NOT EXISTS ip_address TEXT")
    cur.execute("""CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY, message TEXT NOT NULL, is_read BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    cur.close()
    conn.close()


VIEWER_PASSWORD = os.environ.get('VIEWER_PASSWORD')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')


# ---------------- AUDIO FUNCTIONS ----------------

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
    

# ---------------- PHOTO FUNCTIONS ----------------

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


# ---------------- SETTINGS FUNCTIONS ----------------

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
            "session_version": 1
        }

        cur.execute(
            """
            INSERT INTO settings
            (id, heading, viewer_password, admin_password, session_version)
            VALUES (1, %s, %s, %s, %s)
            """,
            (
                settings["heading"],
                settings["viewer_password"],
                settings["admin_password"],
                settings["session_version"]
            )
        )

        conn.commit()

    cur.close()
    conn.close()

    return settings


def save_settings(data):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE settings
        SET heading = %s,
            viewer_password = %s,
            admin_password = %s
        WHERE id = 1
        """,
        (
            data["heading"],
            data["viewer_password"],
            data["admin_password"]
        )
    )

    conn.commit()
    cur.close()
    conn.close()


# ---------------- ACTIVE SESSION FUNCTIONS ----------------

def create_session_record(role):
    session_id = str(uuid.uuid4())
    user_agent = request.headers.get('User-Agent', 'Unknown Device')

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO active_sessions
        (session_id, role, user_agent)
        VALUES (%s, %s, %s)
        """,
        (
            session_id,
            role,
            user_agent
        )
    )

    conn.commit()
    cur.close()
    conn.close()

    session['session_id'] = session_id

    return session_id


def remove_current_session_record():
    session_id = session.get('session_id')

    if not session_id:
        return

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM active_sessions
        WHERE session_id = %s
        """,
        (session_id,)
    )

    conn.commit()
    cur.close()
    conn.close()


def get_active_sessions():
    conn = get_db()
    cur = conn.cursor()

    # Sessions with no activity for 30 minutes are considered inactive
    cur.execute("""
        DELETE FROM active_sessions
        WHERE last_seen < CURRENT_TIMESTAMP - INTERVAL '30 minutes'
    """)

    conn.commit()

    cur.execute("""
        SELECT
            id,
            session_id,
            role,
            user_agent,
            created_at,
            last_seen
        FROM active_sessions
        ORDER BY last_seen DESC
    """)

    sessions = cur.fetchall()

    cur.close()
    conn.close()

    return sessions


def check_session():
    if 'role' not in session:
        return False

    settings = get_settings()

    # Check global session version
    if session.get('session_version') != settings['session_version']:
        remove_current_session_record()
        session.clear()
        return False

    # Check individual session record
    session_id = session.get('session_id')

    if not session_id:
        session.clear()
        return False

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id
        FROM active_sessions
        WHERE session_id = %s
        """,
        (session_id,)
    )

    active_session = cur.fetchone()

    if not active_session:
        cur.close()
        conn.close()
        session.clear()
        return False

    # Update last activity time
    cur.execute(
        """
        UPDATE active_sessions
        SET last_seen = CURRENT_TIMESTAMP
        WHERE session_id = %s
        """,
        (session_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    return True


def client_ip():
    # Render supplies the client address through X-Forwarded-For.
    return request.headers.get("X-Forwarded-For", request.remote_addr or "Unknown").split(",")[0].strip()


def log_event(event, role=None):
    """Record login/logout activity and create a dashboard notification."""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        ip = client_ip()
        cur.execute(
            "INSERT INTO login_history (event, role, user_agent, ip_address) VALUES (%s, %s, %s, %s)",
            (event, role, user_agent, ip)
        )
        cur.execute(
            "INSERT INTO notifications (message) VALUES (%s)",
            (f"{event}" + (f" ({role})" if role else ""),)
        )
        # Keep login/logout history for 7 days.
        cur.execute("DELETE FROM login_history WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'")
        # Delete read notifications after 2 days; delete every notification after 7 days.
        cur.execute("DELETE FROM notifications WHERE is_read = TRUE AND created_at < CURRENT_TIMESTAMP - INTERVAL '2 days'")
        cur.execute("DELETE FROM notifications WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'")
        conn.commit()
        cur.close()
    except Exception:
        app.logger.exception("Could not record login/logout event")
        if conn:
            conn.rollback()
            conn.close()


def get_login_history():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM login_history WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'")
    cur.execute("SELECT * FROM login_history ORDER BY created_at DESC LIMIT 500")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_notifications():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM notifications WHERE is_read = TRUE AND created_at < CURRENT_TIMESTAMP - INTERVAL '2 days'")
    cur.execute("DELETE FROM notifications WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'")
    cur.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT 500")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

# ---------------- LOGIN ----------------

@app.route('/', methods=['GET', 'POST'])
def login():

    if 'role' in session:
        if check_session():
            return redirect(url_for('gallery'))

        session.clear()

    settings = get_settings()
    error = None

    if request.method == 'POST':
        ip = client_ip()
        now = time.time()
        attempts = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 300]
        if len(attempts) >= 8:
            return render_template('index.html', error='Too many attempts. Please wait 5 minutes.'), 429

        pwd = request.form.get('password', '')

        if pwd and pwd == settings['viewer_password']:

            session['role'] = 'viewer'
            session['session_version'] = settings['session_version']

            create_session_record('viewer')
            log_event('Login successful', 'viewer')

            return redirect(url_for('gallery'))

        elif pwd == settings['admin_password']:

            session['role'] = 'admin'
            session['session_version'] = settings['session_version']

            create_session_record('admin')
            log_event('Login successful', 'admin')

            return redirect(url_for('dashboard'))

        else:
            attempts.append(now)
            LOGIN_ATTEMPTS[ip] = attempts
            error = "Wrong password, try again."

    return render_template('index.html', error=error)


# ---------------- GALLERY ----------------

@app.route('/gallery')
def gallery():

    if not check_session():
        return redirect(url_for('login'))

    photos = get_data()
    settings = get_settings()

    return render_template(
        'album.html',
        photos=photos,
        heading=settings['heading']
    )


# ---------------- PRIVATE AUDIO ----------------

@app.route('/private_audio')
def private_audio():

    if not check_session():
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT audio, mime_type
        FROM audio
        ORDER BY id DESC
        LIMIT 1
    """)

    audio = cur.fetchone()

    cur.close()
    conn.close()

    if not audio or not audio['audio']:
        return "Audio not found", 404

    return send_file(
        io.BytesIO(bytes(audio['audio'])),
        mimetype=audio['mime_type']
    )
    

# ---------------- PRIVATE IMAGE ----------------

@app.route('/private_image/<int:photo_id>')
def private_image(photo_id):

    if not check_session():
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT image, mime_type
        FROM photos
        WHERE id = %s
        """,
        (photo_id,)
    )

    photo = cur.fetchone()

    cur.close()
    conn.close()

    if not photo or not photo['image']:
        return "Image not found", 404

    return send_file(
        io.BytesIO(bytes(photo['image'])),
        mimetype=photo['mime_type'] or 'application/octet-stream'
    )


# ---------------- ADMIN DASHBOARD ----------------

@app.route('/dashboard')
def dashboard():

    if not check_session() or session.get('role') != 'admin':
        return redirect(url_for('login'))

    photos = get_data()
    settings = get_settings()

    # Get currently active sessions/devices
    active_sessions = get_active_sessions()

    return render_template(
        'dashboard.html',
        photos=photos,
        settings=settings,
        active_sessions=active_sessions,
        login_history=get_login_history(),
        notifications=get_notifications()
    )


# ---------------- ADD PHOTO ----------------

@app.route('/add_photo', methods=['POST'])
def add_photo():

    if not check_session() or session.get('role') != 'admin':
        return redirect(url_for('login'))

    file = request.files.get('image')
    caption = request.form.get('caption', '').strip()

    if not file or not file.filename:
        flash("Please select an image.")
        return redirect(url_for('dashboard'))

    if not caption:
        flash("Please enter a caption.")
        return redirect(url_for('dashboard'))

    if file.mimetype not in ('image/jpeg', 'image/png', 'image/webp', 'image/gif'):
        flash('Use JPG, PNG, WEBP, or GIF images only.')
        return redirect(url_for('dashboard'))
    image_data = file.read(10 * 1024 * 1024 + 1)
    if len(image_data) > 10 * 1024 * 1024:
        flash('Image must be 10 MB or smaller.')
        return redirect(url_for('dashboard'))

    if not image_data:
        flash("The selected image is empty.")
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    mime_type = file.mimetype or 'application/octet-stream'

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO photos
        (url, caption, image, mime_type, sort_order)
        VALUES (%s, %s, %s, %s, COALESCE((SELECT MAX(sort_order) FROM photos), 0) + 1)
        """,
        (
            filename,
            caption,
            psycopg2.Binary(image_data),
            mime_type
        )
    )

    conn.commit()
    cur.close()
    conn.close()

    flash("Photo added successfully!")

    return redirect(url_for('dashboard'))


# ---------------- ADD AUDIO ----------------

@app.route('/add_audio', methods=['POST'])
def add_audio():

    if not check_session() or session.get('role') != 'admin':
        return redirect(url_for('login'))

    file = request.files.get('audio')

    if not file or not file.filename:
        flash("Please select an audio file.")
        return redirect(url_for('dashboard'))

    audio_data = file.read()

    if not audio_data:
        flash("The selected audio file is empty.")
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    mime_type = file.mimetype or 'audio/mpeg'

    conn = get_db()
    cur = conn.cursor()

    # Keep only one background audio
    cur.execute("DELETE FROM audio")

    cur.execute(
        """
        INSERT INTO audio
        (filename, audio, mime_type)
        VALUES (%s, %s, %s)
        """,
        (
            filename,
            psycopg2.Binary(audio_data),
            mime_type
        )
    )

    conn.commit()
    cur.close()
    conn.close()

    flash("Background audio added successfully!")

    return redirect(url_for('dashboard'))
    

# ---------------- DELETE PHOTO ----------------

@app.route('/delete_photo/<int:photo_id>', methods=['POST'])
def delete_photo(photo_id):

    if not check_session() or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        DELETE FROM photos
        WHERE id = %s
        """,
        (photo_id,)
    )

    conn.commit()
    cur.close()
    conn.close()

    flash("Photo deleted.")

    return redirect(url_for('dashboard'))


# ---------------- UPDATE SETTINGS ----------------

@app.route('/update_settings', methods=['POST'])
def update_settings():

    if not check_session() or session.get('role') != 'admin':
        return redirect(url_for('login'))

    settings = get_settings()

    new_viewer = request.form.get('viewer_password', '').strip()
    new_admin = request.form.get('admin_password', '').strip()
    if new_viewer and len(new_viewer) < 4:
        flash("Viewer password must be at least 4 characters.")
        return redirect(url_for('dashboard'))
    if new_admin and len(new_admin) < 4:
        flash("Admin password must be at least 4 characters.")
        return redirect(url_for('dashboard'))
    password_changed = bool(new_viewer or new_admin)
    if new_viewer:
        settings['viewer_password'] = new_viewer
    if new_admin:
        settings['admin_password'] = new_admin
    settings['heading'] = request.form.get('heading', settings.get('heading', 'Meri Zindagi Hain Tu')).strip() or settings.get('heading', 'Meri Zindagi Hain Tu')

    if password_changed:
        settings['session_version'] = int(settings.get('session_version') or 1) + 1
        # Invalidate other sessions after a password change.
        conn = get_db(); cur = conn.cursor()
        cur.execute("UPDATE settings SET heading=%s, viewer_password=%s, admin_password=%s, session_version=%s WHERE id=1",
                    (settings['heading'], settings['viewer_password'], settings['admin_password'], settings['session_version']))
        cur.execute("DELETE FROM active_sessions")
        conn.commit(); cur.close(); conn.close()
        session.clear()
        flash("Password changed. Please log in again on all devices.")
        return redirect(url_for('login'))
    save_settings(settings)

    flash("Settings updated successfully!")

    return redirect(url_for('dashboard'))


@app.route('/edit_photo/<int:photo_id>', methods=['POST'])
def edit_photo(photo_id):
    if not check_session() or session.get('role') != 'admin': return redirect(url_for('login'))
    caption=request.form.get('caption','').strip()
    try: order=max(1, int(request.form.get('sort_order','1')))
    except ValueError: order=1
    if not caption:
        flash('Caption cannot be empty.'); return redirect(url_for('dashboard'))
    conn=get_db(); cur=conn.cursor()
    cur.execute("UPDATE photos SET caption=%s, sort_order=%s WHERE id=%s",(caption,order,photo_id))
    conn.commit(); cur.close(); conn.close(); flash('Photo caption/order updated.'); return redirect(url_for('dashboard'))

@app.route('/notification/<int:notification_id>/toggle', methods=['POST'])
def toggle_notification(notification_id):
    if not check_session() or session.get('role') != 'admin': return redirect(url_for('login'))
    conn=get_db(); cur=conn.cursor()
    cur.execute("UPDATE notifications SET is_read = NOT is_read WHERE id=%s", (notification_id,))
    conn.commit(); cur.close(); conn.close()
    return redirect(url_for('dashboard'))

@app.route('/notification/<int:notification_id>/delete', methods=['POST'])
def delete_notification(notification_id):
    if not check_session() or session.get('role') != 'admin': return redirect(url_for('login'))
    conn=get_db(); cur=conn.cursor(); cur.execute("DELETE FROM notifications WHERE id=%s", (notification_id,))
    conn.commit(); cur.close(); conn.close(); return redirect(url_for('dashboard'))

@app.route('/mark_notifications_read', methods=['POST'])
def mark_notifications_read():
    if not check_session() or session.get('role') != 'admin': return redirect(url_for('login'))
    conn=get_db(); cur=conn.cursor(); cur.execute("UPDATE notifications SET is_read=TRUE WHERE is_read=FALSE")
    conn.commit(); cur.close(); conn.close(); return redirect(url_for('dashboard'))

@app.route('/login_history/<int:history_id>/delete', methods=['POST'])
def delete_login_history(history_id):
    if not check_session() or session.get('role') != 'admin': return redirect(url_for('login'))
    conn=get_db(); cur=conn.cursor(); cur.execute("DELETE FROM login_history WHERE id=%s", (history_id,))
    conn.commit(); cur.close(); conn.close(); return redirect(url_for('dashboard'))

@app.route('/login_history/clear', methods=['POST'])
def clear_login_history():
    if not check_session() or session.get('role') != 'admin': return redirect(url_for('login'))
    conn=get_db(); cur=conn.cursor(); cur.execute("DELETE FROM login_history")
    conn.commit(); cur.close(); conn.close(); flash('Login history cleared.'); return redirect(url_for('dashboard'))

# ---------------- LOGOUT ALL DEVICES ----------------

@app.route('/logout_all', methods=['POST'])
def logout_all():

    if not check_session() or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()

    # Invalidate every existing login session
    cur.execute("""
        UPDATE settings
        SET session_version = session_version + 1
        WHERE id = 1
    """)

    # Remove all active session records
    cur.execute("""
        DELETE FROM active_sessions
    """)

    conn.commit()
    cur.close()
    conn.close()

    session.clear()

    return redirect(url_for('login'))


# ---------------- LOGOUT ----------------

@app.route('/logout')
def logout():

    if 'role' in session:
        log_event('Logout', session.get('role'))
        remove_current_session_record()

    session.clear()

    return redirect(url_for('login'))


# ---------------- START APP ----------------

init_db()


if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
