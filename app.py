import os
import platform
import subprocess
import bcrypt
import psutil
import mysql.connector
import shutil
import getpass
import socket
from datetime import datetime
from flask import Flask, redirect, session, url_for, render_template, request, flash, send_from_directory
from werkzeug.utils import secure_filename
import dockers
import applications
import time

# Configuration
UPLOAD_FOLDER = 'uploads/'  # Directory where files will be stored
NOT_ALLOWED_EXTENSIONS = {
    # Executables
    '.exe', '.bat', '.cmd', '.sh', '.bin', '.msi', '.com', '.scr',

    # Scripts and Code
    '.php', '.py', '.pl', '.cgi', '.js', '.asp', '.jsp', '.rb',

    # Documents with Macros
    '.docm', '.xlsm', '.pptm',

    # Libraries and Links
    '.dll', '.so', '.dylib', '.lnk',

    # Configuration and System Files
    '.ini', '.conf', '.sys', '.drv', '.inf',

    # Images with Embedded Code
    '.svg', '.ico'
}

ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif'}

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')  # Ensure there's a fallback key for development
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

HOST_DB = os.environ.get('HOST_DB')
USER_DB = os.environ.get('USER_DB')
PASS_DB = os.environ.get('PASS_DB')
DB = os.environ.get('DB')

# Database Functions
def get_db_connection():
    return mysql.connector.connect(
        host=HOST_DB,
        user=USER_DB,
        password=PASS_DB,
        database=DB
    )

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


def create_user(username, password):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("""
                INSERT INTO users (username, password) VALUES (%s, %s)
            """, (username, hashed_password.decode('utf-8')))
            connection.commit()
    finally:
        connection.close()

def get_users_by_name(username):
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username FROM users WHERE username LIKE %s", ("%" + username + "%",))
            return cursor.fetchall()
    finally:
        connection.close()

def get_all_users():
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, username FROM users")
            users = cursor.fetchall()
            return users if users else []
    finally:
        connection.close()

def delete_user(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            # Verifica o número total de usuários
            cursor.execute("SELECT COUNT(*) as total FROM users")
            result = cursor.fetchone()
            if result['total'] <= 1:
                raise Exception("Cannot delete the last remaining user.")

            # Exclui o usuário especificado
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            connection.commit()
    finally:
        connection.close()

def update_user_password(user_id, new_password):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", 
                           (hashed_password.decode('utf-8'), user_id))
            connection.commit()
    finally:
        connection.close()

def apply_wallpaper_and_theme(user_id, wallpaper_path, theme):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO wallpapers_and_theme_for_user (user_id, wallpaper_path, theme) 
                VALUES (%s, %s, %s)
            """, (user_id, wallpaper_path, theme))
            connection.commit()
    finally:
        connection.close()

def get_last_applied_wallpaper_and_theme(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT * FROM wallpapers_and_theme_for_user 
                WHERE user_id = %s ORDER BY applied_at DESC LIMIT 1
            """, (user_id,))
            return cursor.fetchone()
    finally:
        connection.close()

def get_selected_wallpaper_and_theme(user_id):
    connection = get_db_connection()
    try:
        with connection.cursor(dictionary=True) as cursor:
            cursor.execute("""
                SELECT wallpaper_path, theme 
                FROM wallpapers_and_theme_for_user 
                WHERE user_id = %s 
                ORDER BY applied_at DESC LIMIT 1
            """, (user_id,))
            result = cursor.fetchone()
            if result:
                selected_wallpaper_path = "static/wallpapers/" + result['wallpaper_path']
                selected_theme = result['theme']
            else:
                selected_wallpaper_path = ""
                selected_theme = ""
    finally:
        connection.close()
    return selected_wallpaper_path, selected_theme

def log_user_access(user_id, access_level):
    ip_address, os_name, user_agent = get_device_info()
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO access (user_id, access_level, ip_address, os_name, user_agent, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (user_id, access_level, ip_address, os_name, user_agent))
            connection.commit()
    finally:
        connection.close()

# Utility Functions
def allowed_file(filename):
    file_ext = os.path.splitext(filename)[1].lower()
    return file_ext not in NOT_ALLOWED_EXTENSIONS

def check_docker_installed():
    try:
        result = subprocess.run(['docker', '--version'], shell=True, capture_output=True, text=True, check=True)
        # Se o comando for bem-sucedido, o Docker está instalado
        print("Docker está instalado:")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print("Docker não está instalado. Detalhes:")
        print(e.stderr)
        return False
    except FileNotFoundError:
        # Se o comando não for encontrado, o Docker não está instalado
        print("Docker não está instalado. O comando 'docker' não foi encontrado.")
        return False

def get_local_ip():
    try:
        # Conecta-se a um servidor externo (por exemplo, Google DNS) para obter o IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception as e:
        return f"Erro ao tentar obter o IP local: {e}"
    
    return ip

def check_webui_is_installed(host='127.0.0.1', port=8080):
    """Verifica se a porta está aberta no host especificado."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)  # Define um tempo limite para a conexão
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False
        
def check_ollama_is_installed(host='127.0.0.1', port=11434):
    """Verifica se a porta está aberta no host especificado."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)  # Define um tempo limite para a conexão
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError):
            return False

def get_cpu_usage():
    try:
        cpu_usage = psutil.cpu_percent(interval=1)  
        return round(cpu_usage, 2)
    except Exception as e:
        return "Error: " + str(e)

def get_ram_usage():
    try:
        if platform.system() == "Windows":
            ram_usage = psutil.virtual_memory()[2]
            return ram_usage
        else:
            output = subprocess.getoutput("free -m | grep Mem")
            tokens = output.split()
            ram_total = int(tokens[1])
            ram_used = int(tokens[2])
            ram_usage = (ram_used / ram_total) * 100
            return round(ram_usage, 2)
    except Exception as e:
        return "Error: " + str(e)

def get_wifi_signal():
    try:
        if platform.system() == "Windows":
            output = subprocess.getoutput("netsh wlan show interfaces")
            for line in output.splitlines():
                if "Signal" in line:
                    signal_level = line.split(":")[1].strip().replace("%", "")
                    return int(signal_level)
        elif platform.system == "linux":
            output = subprocess.getoutput("nmcli -f SSID,SIGNAL dev wifi")
            for line in output.splitlines():
                if "*" in line:
                    parts = line.split()
                    if len(parts) > 1:
                        signal_level = parts[1].replace('%', '')
                        return int(signal_level)
    except Exception as e:
        return "Error: " + str(e)

def get_device_info():
    user_agent = request.headers.get('User-Agent')
    ip_address = request.remote_addr
    os_name = platform.system()
    return ip_address, os_name, user_agent

# Routes
@app.route('/')
def dashboard():
    user_id = session.get('user_id', None)
    if not user_id:
        return redirect(url_for('login'))

    wallpaper, theme = get_selected_wallpaper_and_theme(user_id)
    cpu_usage = get_cpu_usage()
    ram_usage = get_ram_usage()
    wifi_signal = get_wifi_signal()

    return render_template('dashboard.html',
                           wallpaper=wallpaper,
                           theme=theme,
                           cpu_usage=cpu_usage,
                           ram_usage=ram_usage,
                           wifi_signal=wifi_signal)

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
    
@app.route('/setwt', methods=['GET', 'POST'])
def set_wallpaper_and_theme():
    if request.method == 'POST':
        wallpaper_path = request.form.get('wallpaper')
        theme = request.form.get('theme')
        user_id = session['user_id']

        apply_wallpaper_and_theme(user_id, wallpaper_path, theme)
        flash('Wallpaper and theme updated successfully!', 'success')
    availble_wallpapers = os.listdir("static/wallpapers/")
    selected_wallpaper_path, selected_theme = get_selected_wallpaper_and_theme(session['user_id'])
    return render_template('setwt.html', 
                           availble_wallpapers=availble_wallpapers,
                           selected_wallpaper_path=selected_wallpaper_path, 
                           selected_theme=selected_theme)
    
@app.route('/upload_wallpaper', methods=['GET', 'POST'])
def upload_wallpaper():
    if request.method == 'POST':
        if 'wallpaper' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['wallpaper']
        
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and (os.path.splitext(file.filename)[1].lower() in ALLOWED_EXTENSIONS):
            filename = secure_filename(file.filename)
            file_path = os.path.join("static/wallpapers/", filename)
            file.save(file_path)
            
            flash('Wallpaper successfully uploaded', 'success')
        else:
            flash('File type not allowed', 'danger')
            return redirect(request.url)
    
    return render_template('setwt.html')

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

    wallpaper, theme = get_selected_wallpaper_and_theme(user_id)
    return render_template('settings.html',
                           theme=theme)

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







# Apps

@app.route('/install_docker', methods=['GET', 'POST'])
def install_docker():
    if request.method == 'POST':
        system = platform.system().lower()
        if system == "linux":
            password = request.form['password']
            dockers.install_docker_linux(password)
            flash('Docker instalado com sucesso!', 'success')
        elif system == "windows":
            return render_template('indisponivel.html')
        else:
            return render_template('indisponivel.html')
    return render_template('install_docker.html')


@app.route('/install_docker_app', methods=['POST'])
def install_docker_app():
    app_name = request.form['app_name']
    if app_name == "pihole":
        return redirect(url_for('install_pihole'))
    return redirect(url_for('apps'))


"""
@app.route('/uninstall_container', methods=['POST'])
def uninstall_container():
    system = platform.system().lower()
    if system == "linux":
        container_name = request.form['container_name']
        dockers.run_command(f"docker stop {container_name}")
        dockers.run_command(f"docker rm {container_name}")
        
        # Remove o container do banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM docker_containers WHERE name = %s", (container_name,))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash(f'Container {container_name} desinstalado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    elif system == "windows":
        return render_template('indisponivel.html')
    else:
        return render_template('indisponivel.html')
"""
        
@app.route('/apps')
def apps():
    system = platform.system().lower()
    if system == "windows":
        return render_template('indisponivel.html')
    
    docker_alert = ""
    docker_apps = []
    non_docker_apps = get_non_docker_applications()

    if system == "linux":
        try:
            if check_docker_installed():
                docker_apps = get_docker_applications()
            else:
                return redirect(url_for('install_docker'))
        except Exception as e:
            docker_alert = f"Erro ao obter aplicativos Docker: {str(e)}"
    else:
        return render_template('indisponivel.html')
    return render_template('applications.html', docker_alert=docker_alert, docker_apps=docker_apps, non_docker_apps=non_docker_apps)

def get_docker_applications():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, port, installed, icon FROM docker_containers")
    containers = cursor.fetchall()
    cursor.close()
    conn.close()

    apps = [
        {
            'name': container[0],
            'port': container[1],
            'installed' : container[2],
            'icon': container[3] if container[3] is not None else '/static/icons/default_app.png'
        }
        for container in containers
    ]
    return apps

def get_non_docker_applications():
    global ollama_is_installed
    return [
    {'name': 'ollama', 'install_route':'install_ollama', 'port': 8080, 'installed': check_webui_is_installed()}
    ]


@app.route('/view')
def view():
    system = platform.system().lower()
    if system == "linux":
        if check_docker_installed():
            docker_apps = get_docker_applications()
            non_docker_apps = get_non_docker_applications()
            if check_ollama_is_installed():
                return render_template('view.html', docker_apps=docker_apps, non_docker_apps=non_docker_apps, ip=get_local_ip())
            else:
                return redirect(url_for('start_ollama'))
        else:
            return redirect(url_for('install_docker'))
    else:
        return render_template('indisponivel.html')


@app.route('/start_ollama', methods=['GET', 'POST'])
def start_ollama():
    system = platform.system().lower()
    if system == "linux":
        if check_docker_installed():
            if request.method == 'POST':
                passw = request.form['password']
                dockers.start_ollama_container(passw)
                return redirect(url_for('view'))
            return render_template('start_ollama.html')
        else:
            return redirect(url_for('install_docker'))
    else:
        return render_template('indisponivel.html')

@app.route('/install_ollama', methods=['POST'])
def install_ollama():
    global ollama_is_installed
    system = platform.system().lower()
    if system == "linux":
        if check_docker_installed():
            if request.method == 'POST':
                passw = request.form['password']
                dockers.run_ollama_container(passw)
                dockers.run_openwebui_container(passw)
                ollama_is_installed = True
                return redirect(url_for('view'))
            return render_template('install_ollama.html')
        else:
            return redirect(url_for('install_docker'))
    else:
        return render_template('indisponivel.html')
    
@app.route('/install_pihole', methods=['GET', 'POST'])
def install_pihole():
    if request.method == 'POST':
        # Obtém a senha do formulário
        passw = request.form['password']
        
        # Adiciona o Pi-hole ao banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE docker_containers SET installed=TRUE WHERE name = 'pihole';")
        conn.commit()
        cursor.close()
        conn.close()
        
        # Executa o comando para rodar o container Pi-hole com a senha fornecida
        dockers.run_pihole_container(passw)
        
        flash('Pi-hole instalado com sucesso!', 'success')
        return redirect(url_for('view'))
    
    # Renderiza o template com o formulário de instalação
    return render_template('install_pihole.html')

        
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = get_db_connection()
        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                    session['logged_in'] = True
                    session['user_id'] = user['id']

                    log_user_access(user['id'], 'Login Successful')
                    return redirect(url_for('dashboard'))
                else:
                    return render_template('login.html', error=True)
        finally:
            connection.close()

    return render_template('login.html')

@app.before_request
def check_login():
    public_endpoints = ['login']
    if 'logged_in' not in session and request.endpoint not in public_endpoints:
        return redirect(url_for('login'))

# Application Entry Point
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=9900)
