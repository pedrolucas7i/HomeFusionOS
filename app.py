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
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')  # Make sure the SECRET_KEY is set in .env
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Getting the environment variables
HOST_DB = os.environ.get('HOST_DB', 'localhost')
USER_DB = os.environ.get('USER_DB', 'root')
PASS_DB = os.environ.get('PASS_DB', '')
DB = os.environ.get('DB', 'homefusionOS')

# Function to check and create the database if it doesn't exist
def create_database_if_not_exists():
    try:
        with pymysql.connect(host=HOST_DB, user=USER_DB, password=PASS_DB) as connection:
            with connection.cursor() as cursor:
                cursor.execute(f"SHOW DATABASES LIKE '{DB}';")
                result = cursor.fetchone()

                if result:
                    print(f'The database {DB} already exists.')
                else:
                    print(f'The database {DB} does not exist. Creating...')
                    cursor.execute(f"CREATE DATABASE {DB};")
                    print(f'Database {DB} created successfully.')
    except pymysql.MySQLError as e:
        print(f'Error connecting to MySQL: {e}')

# Configuring the URI for the MariaDB database
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{USER_DB}:{PASS_DB}@{HOST_DB}:3306/{DB}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Create the database if it doesn't exist
create_database_if_not_exists()

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
def create_new_user(username, password):
    hashed_password = generate_password_hash(password)  # Default method is 'pbkdf2:sha256'
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

# Check for the first user and create one if it doesn't exist
def check_and_create_first_user():
    first_user = User.query.first()
    if not first_user:  # If no user exists
        print("No user found. Creating default admin user.")
        create_new_user('admin', 'adminpassword')  # Create a default admin user
        print("Default admin user created.")

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
    folder = request.args.get('folder', '')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)
    if os.path.exists(file_path):
        return send_from_directory(os.path.dirname(file_path), filename, as_attachment=True)
    else:
        flash('File not found', 'danger')
        return redirect(url_for('files', folder=folder))


@app.route('/delete/<path:filename>', methods=['POST'])
def delete_file(filename):
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

@app.route('/user_management', methods=['GET', 'POST'])
def user_management():
    users = get_all_users()
    if users is None:
        users = []
    return render_template('user_management.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user_route(user_id):
    try:
        delete_user(user_id)
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('user_management'))

@app.route('/update_password/<int:user_id>', methods=['POST'])
def update_password_route(user_id):
    new_password = request.form['new_password']
    update_user_password(user_id, new_password)
    flash('Password updated successfully!', 'success')
    return redirect(url_for('user_management'))

@app.route('/create_user', methods=['POST'])
def create_user_route():
    username = request.form['username']
    password = request.form['password']
    create_user(username, password)
    flash('User created successfully!', 'success')
    return redirect(url_for('user_management'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))

    return render_template('settings.html')

@app.route('/prompt', methods=['GET', 'POST'])
def prompt():
    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))
    if platform.system() == "Windows":
        userhostfile = os.getcwd() + " $ "
    else:
        userhostfile = getpass.getuser() + "@" + socket.gethostname() + ":/" + os.path.basename(os.getcwd()) + "$ "
    if request.method == 'POST':
        command = request.form['command']
        try:
            result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8") + result.stderr.decode("utf-8")
        except Exception as e:
            output = str(e)

        return render_template('prompt.html',
                               userhostfile=userhostfile,
                               output=output)
    return render_template('prompt.html',
                           userhostfile=userhostfile,
                           output="")

@app.route('/apps')
def apps():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('apps.html')

@app.route('/apps/<string:app_name>')
def apps2():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=9900)
