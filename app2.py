from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import pymysql
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash

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
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        if user and (user.password == password):
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

# Dashboard route (protected by login_required)
@app.route('/')
def dashboard():
    if 'logged_in' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
