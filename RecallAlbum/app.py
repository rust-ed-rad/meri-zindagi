import psycopg2
from psycopg2.extras import RealDictCursor
import json
import os
import io
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

DATA_FILE = 'data.json'
SETTINGS_FILE = 'settings.json'
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS photos (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        caption TEXT NOT NULL,
        image BYTEA
    )
""")

cur.execute("""
    ALTER TABLE photos
    ADD COLUMN IF NOT EXISTS image BYTEA
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

# --- HELPER FUNCTIONS TO READ/WRITE FILES ---
def get_data():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, url, caption FROM photos ORDER BY id")
    photos = cur.fetchall()

    cur.close()
    conn.close()

    return photos


def save_data(data):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM photos")

    for photo in data:
        cur.execute(
            "INSERT INTO photos (url, caption) VALUES (%s, %s)",
            (photo["url"], photo["caption"])
        )

    conn.commit()
    cur.close()
    conn.close()


def get_settings():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT heading, viewer_password, admin_password FROM settings WHERE id = 1")
    settings = cur.fetchone()

    if not settings:
        settings = {
            "heading": "Our Memories",
            "viewer_password": VIEWER_PASSWORD,
            "admin_password": ADMIN_PASSWORD
        }

        cur.execute(
            """
            INSERT INTO settings (id, heading, viewer_password, admin_password)
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

# --- ROUTES ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'role' in session: return redirect(url_for('gallery'))
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

@app.route('/gallery')
def gallery():
    if 'role' not in session: return redirect(url_for('login'))
    photos = get_data()
    settings = get_settings()
    return render_template('album.html', photos=photos, heading=settings['heading'])

@app.route('/private_image/<int:photo_id>')
def private_image(photo_id):
    if 'role' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT image FROM photos WHERE id = %s", (photo_id,))
    photo = cur.fetchone()

    cur.close()
    conn.close()

    if not photo or not photo['image']:
        return "Image not found", 404

    return send_file(
        io.BytesIO(bytes(photo['image'])),
        mimetype='image/jpeg'
    )

@app.route('/dashboard')
def dashboard():
    if 'role' not in session or session['role'] != 'admin': return redirect(url_for('login'))
    photos = get_data()
    settings = get_settings()
    return render_template('dashboard.html', photos=photos, settings=settings)

@app.route('/add_photo', methods=['POST'])
def add_photo():
    if 'role' not in session or session['role'] != 'admin': return redirect(url_for('login'))
    url = request.form.get('url')
    caption = request.form.get('caption')
    if url and caption:
        data = get_data()
        data.append({"url": url, "caption": caption})
        save_data(data)
        flash("Photo added successfully!")
    return redirect(url_for('dashboard'))

@app.route('/delete_photo/<int:index>')
def delete_photo(index):
    if 'role' not in session or session['role'] != 'admin': return redirect(url_for('login'))
    data = get_data()
    if 0 <= index < len(data):
        data.pop(index)
        save_data(data)
        flash("Photo deleted.")
    return redirect(url_for('dashboard'))

@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'role' not in session or session['role'] != 'admin': return redirect(url_for('login'))
    settings = get_settings()
    settings['viewer_password'] = request.form.get('viewer_password')
    settings['admin_password'] = request.form.get('admin_password')
    settings['heading'] = request.form.get('heading')
    save_settings(settings)
    flash("Settings updated successfully!")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

init_db()

if __name__ == '__main__':
    import os

app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 10000))
)
