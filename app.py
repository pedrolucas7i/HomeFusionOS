import os
import platform
import subprocess
import bcrypt
import psutil
import shutil
import getpass
import socket
import time
import json
import requests
import re
import threading
from datetime import datetime
from collections import defaultdict
import eventlet
import eventlet.wsgi
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import pty

load_dotenv()

child_fd = None

defaultsecret='HomeFusionOS2025'
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', defaultsecret)
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Database configuration for SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///homefusionOS.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

socketio = SocketIO(app, async_mode='eventlet')

OFFLINE_JSON_PATH = "dockers-conf/dockers.json"
apps_data = defaultdict(list)
app_ports = {}

ICON_OVERRIDES = {
    "pi-hole": "pihole", "adguard-home": "adguard", "tailscale": "tailscale",
    "nginx-proxy-manager": "nginxproxymanager", "nextcloud": "nextcloud",
    "syncthing": "syncthing", "duplicati": "duplicati", "jellyfin": "jellyfin",
    "sonarr": "sonarr", "radarr": "radarr", "qbittorrent-nox": "qbittorrent",
    "navidrome": "navidrome", "grafana": "grafana", "netdata": "netdata",
    "uptime-kuma": "uptimekuma", "portainer": "portainer", "watchtower": "watchtower",
    "vaultwarden": "vaultwarden", "home-assistant": "homeassistant",
    "paperless-ngx": "paperlessngx", "searxng": "searxng", "firefly-iii": "fireflyiii",
    "gitea": "gitea", "code-server": "codeserver"
}

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

class Access(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(80), nullable=True)
    time = db.Column(db.DateTime, nullable=True)

class App(db.Model):
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    name = db.Column(db.String(80), nullable=True)
    path = db.Column(db.String(255), nullable=True)

with app.app_context():
    db.create_all()

# User helpers
def create_user(username, password):
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

def update_password(username, new_password):
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()

def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()

def check_and_create_first_user():
    if not User.query.first():
        print("No user found. Creating default admin user.")
        create_user('admin', 'adminpassword')
        print("Default admin user created.")

def get_users():
    return User.query.all()

with app.app_context():
    check_and_create_first_user()

def cpu_usage():
    return psutil.cpu_percent(interval=1)

def ram_usage():
    return round(psutil.virtual_memory()[3]/1000000000, 2)

def get_active_interface():
    try:
        # Get the current local IP address (not loopback)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))  # Connect to a public IP to get the local IP used
        local_ip = s.getsockname()[0]
        s.close()

        # Use 'ip' command to list all interfaces and their IP addresses
        ip_output = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show']).decode('utf-8')
        for line in ip_output.splitlines():
            parts = line.split()
            iface = parts[1]
            ip = parts[3].split('/')[0]
            if ip == local_ip:
                return iface  # Return the interface that matches the current local IP
    except Exception:
        return None

def get_wifi_signal_percentage():
    interface = get_active_interface()
    if not interface:
        return None

    try:
        # Use iwconfig to get signal level for the active interface
        iwconfig_output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.DEVNULL).decode('utf-8')
        signal_strength = re.search(r"Signal level=(-\d+)", iwconfig_output)
        if signal_strength:
            rssi = int(signal_strength.group(1))
            min_rssi, max_rssi = -90, -30  # Typical RSSI range for Wi-Fi
            percentage = ((rssi - min_rssi) / (max_rssi - min_rssi)) * 100
            return round(percentage)  # Convert RSSI to percentage
        return None
    except subprocess.CalledProcessError:
        return None

# Dashboard route (protected by login_required)
@app.route('/')
def dashboard():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html',
                           cpu_usage=cpu_usage(),
                           ram_usage=ram_usage(),
                           wifi_signal=None,
                           wallpaper='static/wallpapers/homefusionOS.jpg')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# File and folder helpers
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_folder(folder_name):
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

def list_files_and_folders(path):
    """ List all files and folders in a directory. """
    try:
        if not os.path.exists(path):
            raise FileNotFoundError("The directory does not exist.")
        entries = os.listdir(path)
        files = [entry for entry in entries if os.path.isfile(os.path.join(path, entry))]
        folders = [entry for entry in entries if os.path.isdir(os.path.join(path, entry))]
        return files, folders
    except Exception as e:
        flash('Error retrieving files and folders: ' + str(e), 'danger')
        return [], []

@app.route('/files/', defaults={'folder': 'root'})
@app.route('/files/<path:folder>', methods=['GET', 'POST'])
def files(folder):
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    # Caminho completo para a pasta atual
    current_folder = os.path.join(app.config['UPLOAD_FOLDER'], folder)

    # Garantir que a pasta existe
    if not os.path.exists(current_folder):
        os.makedirs(current_folder)

    if request.method == 'POST':
        # Upload de arquivo
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_folder, filename)
                file.save(file_path)
                flash('File uploaded successfully', 'success')
            else:
                flash('File type not allowed', 'danger')

        # Criação de nova pasta
        elif 'new_folder' in request.form:
            new_folder = request.form['new_folder'].strip()
            if new_folder and new_folder.lower() != 'uploads':  # Impedir criação de pasta chamada "uploads"
                new_folder_path = os.path.join(current_folder, new_folder)
                if not os.path.exists(new_folder_path):
                    os.makedirs(new_folder_path)
                    flash('Folder created successfully', 'success')
                else:
                    flash('Folder already exists', 'danger')
            else:
                flash('Invalid folder name.', 'danger')

        return redirect(url_for('files', folder=folder))

    # Obtenha arquivos e pastas na pasta atual
    files, folders = list_files_and_folders(current_folder)

    # Diretório pai
    parent_folder = None if folder == "" else os.path.dirname(folder)

    return render_template('files.html',
                           current_folder=folder,
                           files=files,
                           folders=folders,
                           parent_folder=parent_folder)

@app.route('/download/<path:filename>', methods=['GET'])
def download_file(filename):
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    folder = request.args.get('folder', '')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)
    if os.path.exists(file_path):
        return send_from_directory(os.path.dirname(file_path), filename, as_attachment=True)
    else:
        flash('File not found', 'danger')
        return redirect(url_for('files', folder=folder))


@app.route('/delete/<path:filename>', methods=['POST'])
def delete_file(filename):
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    folder = request.form['folder']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)
    if os.path.isfile(file_path):
        os.remove(file_path)
        flash('File deleted successfully', 'success')
    else:
        flash('File not found', 'danger')
    return redirect(url_for('files', folder=folder))

@app.route('/delete_folder', methods=['POST'])
def delete_folder():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    folder_to_delete = request.form['folder']
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder_to_delete)
    if os.path.isdir(folder_path):
        try:
            shutil.rmtree(folder_path)  # Remove a pasta e seu conteúdo
            flash('Folder deleted successfully', 'success')
        except Exception as e:
            flash(f'Error deleting folder: {str(e)}', 'danger')
    else:
        flash('Folder not found', 'danger')
    return redirect(url_for('files'))

@app.route('/create_folder', methods=['POST'])
def create_folder_route():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    folder = request.form['folder']
    new_folder = request.form['new_folder']
    new_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, new_folder)
    if not os.path.exists(new_folder_path):
        os.makedirs(new_folder_path)
        flash('Folder created successfully', 'success')
    else:
        flash('Folder already exists', 'danger')
    return redirect(url_for('files', folder=folder))

@app.errorhandler(405)
def method_not_allowed(e):
    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))
    
    # Verificar se o erro 405 ocorreu na rota /files/
    if request.path.startswith('/files'):
        flash('It is not allowed to create files in the root directory.', 'danger')
        return redirect(url_for('files'))
    # Caso contrário, delegar ao manipulador global ou retornar uma resposta padrão
    return "Method Not Allowed", 405


# Settings and user management routes
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'create_new_user' in request.form:
            create_user(request.form['new_username'], request.form['new_password'])
        elif 'update_password' in request.form:
            update_password(request.form['user_username'], request.form['new_password'])
        elif 'delete_user' in request.form:
            delete_user(request.form['username_to_delete'])
        return redirect(url_for('settings'))

    return render_template('settings.html', users=get_users())


# Shell

def read_and_emit_output(fd):
    while True:
        try:
            data = os.read(fd, 1024).decode()  # Read terminal output
            if data:
                socketio.emit('shell_output', data)  # Send output to frontend
            else:
                break
        except OSError:
            break

@app.route('/prompt', methods=['GET', 'POST'])

def prompt():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))
    
    userhostfile = os.getlogin() + "@" + socket.gethostname() + ":/" + os.path.basename(os.getcwd()) + "$ "
    return render_template('prompt.html', userhostfile=userhostfile, output="")


@app.route('/shell')
def terminal():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('xterm.html')  # Load the terminal in the frontend

def read_and_emit_output(fd):
    while True:
        try:
            data = os.read(fd, 1024).decode()
            socketio.emit('shell_output', data)
        except OSError:
            break

# Handle terminal input
@socketio.on('shell_input')
def handle_terminal_input(data):
    global child_fd
    if child_fd:
        os.write(child_fd, data.encode())  # Write the input to the terminal

@socketio.on('connect')
def start_terminal(auth=None):
    global child_fd

    # Check if a terminal is already running
    if child_fd:
        socketio.emit('shell_output', "Terminal already started.")
        return

    pid, child_fd = pty.fork()  # Create a new terminal (fork)
    if pid == 0:
        os.execvp("bash", ["bash"])  # Execute bash in the child terminal
    else:
        # Start a thread to read terminal output
        threading.Thread(target=read_and_emit_output, args=(child_fd,), daemon=True).start()

# Load apps from the local JSON file
def load_offline_apps():
    global apps_data
    if not apps_data:
        try:
            with open(OFFLINE_JSON_PATH, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
                grouped = defaultdict(list)

                # Load apps from each category in the raw data
                for category in raw_data.keys():
                    for app in raw_data.get(category, []):
                        app["icon_url"] = get_icon_url(app["name"])
                        app["install_script"] = app.get("install_script")
                        grouped[app["namespace"]].append(app)

                apps_data = grouped
                print(f"Loaded {sum(len(v) for v in grouped.values())} apps from local file.")  # Debugging line
        except Exception as e:
            print(f"Error reading JSON file: {e}")
            apps_data = defaultdict(list)

    print(apps_data)
    return apps_data

def get_icon_url(name):
    clean_name = name.lower().replace(" ", "").replace(".", "").replace("-", "")
    return f"https://cdn.simpleicons.org/{clean_name}"


def save_offline_apps(data):
    try:
        with open(OFFLINE_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print("App data saved successfully.")
    except Exception as e:
        print(f"Error saving app data: {e}")

# Route to display all apps
@app.route('/apps')
def all_apps():
    apps_by_namespace = load_offline_apps()
    print(apps_by_namespace) 
    return render_template('apps.html', apps_by_namespace=apps_by_namespace)


# Route to display details of a specific app
@app.route('/app/<app_name>')
def app_details(app_name):
    for namespace, apps in load_offline_apps().items():
        for app in apps:
            if app['name'].lower() == app_name.lower():
                script = app['install_script']
                return render_template('app_details.html', app=app, install_script=script)
    return "App not found!", 404


# Route to fetch all apps (used for refresh or frontend calls)
@app.route('/fetch_new_apps')
def fetch_new_apps():
    return jsonify(load_offline_apps())

# Route to search apps by name
@app.route('/search', methods=['GET'])
def search():
    search_value = request.args.get('search-value', '').strip().lower()
    filtered = defaultdict(list)

    return render_template('apps.html', apps_by_namespace=filtered)

# Route to install an app via Docker using the docker_image from JSON
@app.route('/install/<app_name>', methods=['POST'])
def install_app_route(app_name):
    try:
        apps_data = load_offline_apps()

        # Search and modify the right app
        for namespace, app_list in apps_data.items():
            for app in app_list:
                if app['name'].lower() == app_name.lower():
                    install_script = app.get('install_script')

                    if not install_script:
                        return jsonify({"success": False, "error": "No install script found!"}), 400

                    result = subprocess.run(install_script, shell=True, capture_output=True, text=True, check=True)


                    # ✅ Set installed = true and save the file
                    app['installed'] = True
                    save_offline_apps(apps_data)

                    return jsonify({"success": True, "output": result.stdout.strip()})

        return jsonify({"success": False, "error": "App not found!"}), 404

    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": e.stderr.strip()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


if __name__ == '__main__':
	socketio.run(app, debug=True, host='0.0.0.0', port=9900)
