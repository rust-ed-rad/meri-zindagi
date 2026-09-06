import json
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

DATA_FILE = 'data.json'
SETTINGS_FILE = 'settings.json'

VIEWER_PASSWORD = os.environ.get('VIEWER_PASSWORD')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

# --- HELPER FUNCTIONS TO READ/WRITE FILES ---
def get_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f: json.dump([], f)
    with open(DATA_FILE, 'r') as f: return json.load(f)

def get_settings():
    if not os.path.exists(SETTINGS_FILE):
        default = {"heading": "Our Memories"}
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(default, f, indent=4)

    with open(SETTINGS_FILE, 'r') as f:
        settings = json.load(f)

    settings['viewer_password'] = VIEWER_PASSWORD
    settings['admin_password'] = ADMIN_PASSWORD

    return settings

def save_settings(data):
    data.pop('viewer_password', None)
    data.pop('admin_password', None)

    with open(SETTINGS_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def save_data(data):
    with open(DATA_FILE, 'w') as f: json.dump(data, f, indent=4)

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

@app.route('/private_image/<filename>')
def private_image(filename):
    if 'role' not in session:
        return redirect(url_for('login'))

    from flask import send_from_directory
    return send_from_directory('static/images', filename)

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

if __name__ == '__main__':
    import os

app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 10000))
)
