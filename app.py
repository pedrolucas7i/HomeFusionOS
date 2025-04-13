import os
import platform
import subprocess
import bcrypt
import psutil
import mysql.connector
import shutil
import getpass
import socket
import pymysql
import time
import json
import requests
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from collections import defaultdict
from flask_socketio import SocketIO, emit
import os, pty, select, subprocess, getpass, socket, platform, threading


load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')  # Make sure the SECRET_KEY is set in .env
app.config['UPLOAD_FOLDER'] = 'uploads/'

socketio = SocketIO(app)

OFFLINE_JSON_PATH = "dockers-conf/dockers.json"
apps_data = defaultdict(list)
app_ports = {}

ICON_OVERRIDES = {
    "pi-hole": "pihole",
    "adguard-home": "adguard",
    "tailscale": "tailscale",
    "nginx-proxy-manager": "nginxproxymanager",
    "nextcloud": "nextcloud",
    "syncthing": "syncthing",
    "duplicati": "duplicati",
    "jellyfin": "jellyfin",
    "sonarr": "sonarr",
    "radarr": "radarr",
    "qbittorrent-nox": "qbittorrent",
    "navidrome": "navidrome",
    "grafana": "grafana",
    "netdata": "netdata",
    "uptime-kuma": "uptimekuma",
    "portainer": "portainer",
    "watchtower": "watchtower",
    "vaultwarden": "vaultwarden",
    "home-assistant": "homeassistant",
    "paperless-ngx": "paperlessngx",
    "searxng": "searxng",
    "firefly-iii": "fireflyiii",
    "gitea": "gitea",
    "code-server": "codeserver"
}

# Configuring the URI for the MariaDB database
# SQLite 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///homefusionOS.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Defining models (tables) in MariaDB with SQLAlchemy
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

# Helper function to create a new user
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
    else:
        print("User not found.")

def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
    else:
        print("User not found")

# Check for the first user and create one if it doesn't exist
def check_and_create_first_user():
    first_user = User.query.first()
    if not first_user:  # If no user exists
        print("No user found. Creating default admin user.")
        create_user('admin', 'adminpassword')  # Create a default admin user
        print("Default admin user created.")

def get_users():
    return User.query.all()

def get_running_docker_containers():
    """Obtém uma lista de containers Docker em execução com suas portas mapeadas."""
    try:
        # Executa o comando docker ps para listar containers e suas portas
        result = subprocess.run(['docker', 'ps', '--format', '{{.Names}} {{.Ports}}'], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Divide a saída por linhas (cada linha é um container com o nome e as portas)
        containers = result.stdout.splitlines()
        
        # Cria um dicionário com o nome do container e a porta mapeada
        container_info = {}
        for container in containers:
            parts = container.split()
            name = parts[0]
            ports = parts[1] if len(parts) > 1 else "No ports"
            container_info[name] = ports
        
        return container_info
    except subprocess.CalledProcessError as e:
        print(f"Erro ao listar containers Docker: {e}")
        return {}

with app.app_context():
    check_and_create_first_user()  # Ensure a user exists when the app starts

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # Use check_password_hash
            # If the user exists and password is correct, set the session
            session['logged_in'] = True
            session['user_id'] = user.id

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # If authentication fails, show an error
            flash('Invalid credentials. Please try again.', 'danger')
            return render_template('login.html', error=True)

    return render_template('login.html')

def cpu_usage():
    return psutil.cpu_percent(interval=1)

def ram_usage():
    return round(psutil.virtual_memory()[3]/1000000000, 2)

def get_wifi_signal_percentage(interface='wlan0'):
    try:
        # Run iwconfig to get information about the interface
        iwconfig_output = subprocess.check_output(['iwconfig', interface]).decode('utf-8')
        
        # Look for signal strength in the output
        signal_strength = re.search(r"Signal level=(-\d+)", iwconfig_output)
        
        if signal_strength:
            rssi = int(signal_strength.group(1))
            
            # Convert RSSI to percentage
            min_rssi = -90  # Minimum signal strength
            max_rssi = -30  # Maximum signal strength
            
            # Map RSSI to percentage (0 to 100)
            percentage = ((rssi - min_rssi) / (max_rssi - min_rssi)) * 100
            return round(percentage)
        else:
            print("Signal strength not found.")
            return None
    except subprocess.CalledProcessError as e:
        print(f"Error calling iwconfig: {e}")
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
                            wifi_signal=get_wifi_signal_percentage(),
                            wallpaper='static/wallpapers/homefusionOS.jpg')

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


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'create_new_user' in request.form:
            username = request.form['new_username']
            password = request.form['new_password']
            print(f"Creating user: {username} Password: {password}")
            create_user(username, password)

        elif 'update_password' in request.form:
            username = request.form['user_username']
            password = request.form['new_password']
            print(f"Updating {username} password to: {password}")
            update_password(username, password)

        elif 'delete_user' in request.form:
            username = request.form['username_to_delete']
            print(f"Deleting user: {username}")
            delete_user(username)

        return redirect(url_for('settings'))

    return render_template('settings.html', users=get_users())

@app.route('/prompt', methods=['GET', 'POST'])
def prompt():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))

    if platform.system() == "Windows":
        userhostfile = os.getcwd() + " $ "
    else:
        userhostfile = getpass.getuser() + "@" + socket.gethostname() + ":/" + os.path.basename(os.getcwd()) + "$ "

    return render_template('prompt.html', userhostfile=userhostfile, output="")  # keeping your old prompt.html

@app.route('/shell')
def terminal():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
    return render_template('xterm.html')

def read_and_emit_output(fd):
    while True:
        try:
            data = os.read(fd, 1024).decode()
            socketio.emit('shell_output', data)
        except OSError:
            break

@socketio.on('shell_input')
def handle_terminal_input(data):
    global child_fd
    os.write(child_fd, data.encode())

@socketio.on('connect')
def start_terminal():
    global child_fd
    pid, child_fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash"])
    else:
        threading.Thread(target=read_and_emit_output, args=(child_fd,)).start()

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
    app.run(debug=True, host="0.0.0.0", port=9900)