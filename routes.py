from flask import render_template, request, redirect, url_for, flash, session, Flask
from models import User, WallpaperAndThemeForUser , DockerContainer
from utils import get_selected_wallpaper_and_theme, get_all_users, create_user, delete_user, update_user_password, apply_wallpaper_and_theme, log_user_access
from app import app

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    wallpaper, theme = get_selected_wallpaper_and_theme(user_id)
    return render_template('dashboard.html', wallpaper=wallpaper, theme=theme)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            log_user_access(user.id, 'Login Successful')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/user_management', methods=['GET', 'POST'])
def user_management():
    users = get_all_users()
    return render_template('user_management.html', users=users)

@app.route('/create_user', methods=['POST'])
def create_user_route():
    username = request.form['username']
    password = request.form['password']
    create_user(username, password)
    flash('User  created successfully!', 'success')
    return redirect(url_for('user_management'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user_route(user_id):
    try:
        delete_user(user_id)
        flash('User  deleted successfully!', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('user_management'))

@app.route('/update_password/<int:user_id>', methods=['POST'])
def update_password_route(user_id):
    new_password = request.form['new_password']
    update_user_password(user_id, new_password)
    flash('Password updated successfully!', 'success')
    return redirect(url_for('user_management'))

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
    return render_template('setwt.html', availble_wallpapers=availble_wallpapers, selected_wallpaper_path=selected_wallpaper_path, selected_theme=selected_theme)