import psycopg2
from psycopg2.extras import RealDictCursor
import os
import io
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

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
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            heading TEXT NOT NULL,
            viewer_password TEXT,
            admin_password TEXT
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


VIEWER_PASSWORD = os.environ.get('VIEWER_PASSWORD')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')


# ---------------- PHOTO FUNCTIONS ----------------

def get_data():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, url, caption
        FROM photos
        ORDER BY id
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
        SELECT heading, viewer_password, admin_password
        FROM settings
        WHERE id = 1
    """)

    settings = cur.fetchone()

    if not settings:
        settings = {
            "heading": "Our Memories",
            "viewer_password": VIEWER_PASSWORD,
            "admin_password": ADMIN_PASSWORD
        }

        cur.execute(
            """
            INSERT INTO settings
            (id, heading, viewer_password, admin_password)
            VALUES (1, %s, %s, %s)
            """,
            (
                settings["heading"],
                settings["viewer_password"],
                settings["admin_password"]
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


# ---------------- LOGIN ----------------

@app.route('/', methods=['GET', 'POST'])
def login():

    if 'role' in session:
        return redirect(url_for('gallery'))

    settings = get_settings()
    error = None

    if request.method == 'POST':

        pwd = request.form.get('password')

        if pwd == settings['viewer_password']:
            session['role'] = 'viewer'
            return redirect(url_for('gallery'))

        elif pwd == settings['admin_password']:
            session['role'] = 'admin'
            return redirect(url_for('dashboard'))

        else:
            error = "Wrong password, try again."

    return render_template('index.html', error=error)


# ---------------- GALLERY ----------------

@app.route('/gallery')
def gallery():

    if 'role' not in session:
        return redirect(url_for('login'))

    photos = get_data()
    settings = get_settings()

    return render_template(
        'album.html',
        photos=photos,
        heading=settings['heading']
    )


# ---------------- PRIVATE IMAGE ----------------

@app.route('/private_image/<int:photo_id>')
def private_image(photo_id):

    if 'role' not in session:
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

    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    photos = get_data()
    settings = get_settings()

    return render_template(
        'dashboard.html',
        photos=photos,
        settings=settings
    )


# ---------------- ADD PHOTO ----------------

@app.route('/add_photo', methods=['POST'])
def add_photo():

    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    file = request.files.get('image')
    caption = request.form.get('caption', '').strip()

    if not file or not file.filename:
        flash("Please select an image.")
        return redirect(url_for('dashboard'))

    if not caption:
        flash("Please enter a caption.")
        return redirect(url_for('dashboard'))

    image_data = file.read()

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
        (url, caption, image, mime_type)
        VALUES (%s, %s, %s, %s)
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


# ---------------- DELETE PHOTO ----------------

@app.route('/delete_photo/<int:photo_id>')
def delete_photo(photo_id):

    if 'role' not in session or session['role'] != 'admin':
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

    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    settings = get_settings()

    settings['viewer_password'] = request.form.get('viewer_password')
    settings['admin_password'] = request.form.get('admin_password')
    settings['heading'] = request.form.get('heading')

    save_settings(settings)

    flash("Settings updated successfully!")

    return redirect(url_for('dashboard'))


# ---------------- LOGOUT ----------------

@app.route('/logout')
def logout():

    session.clear()

    return redirect(url_for('login'))


# ---------------- START APP ----------------

init_db()


if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
