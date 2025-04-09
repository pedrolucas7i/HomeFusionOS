from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import logging

# Initialize the SQLAlchemy object
db = SQLAlchemy()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    access = relationship('Access', backref='user', lazy=True)
    wallpapers_and_themes = relationship('WallpaperAndThemeForUser ', backref='user', lazy=True)

class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    access_level = db.Column(db.String(50))
    ip_address = db.Column(db.String(45))
    os_name = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())

class WallpaperAndThemeForUser (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False)
    wallpaper_path = db.Column(db.String(255))
    theme = db.Column(db.String(50))
    applied_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())

class DockerContainer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    port = db.Column(db.String(255), nullable=False)
    installed = db.Column(db.Boolean, default=False)
    icon = db.Column(db.String(255), nullable=True)

def initialize_db(app):
    """Initialize the database and create the first user if none exists."""
    with app.app_context():
        try:
            # Create all tables if they do not exist
            db.create_all()  
            # Check if the first user exists
            create_first_user()  
            logging.info("Database initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing the database: {e}")

def create_first_user():
    """Create the first user if no users exist."""
    if User.query.count() == 0:
        first_user = User(username="admin", password=hash_password("adminpassword"))
        try:
            db.session.add(first_user)
            db.session.commit()
            logging.info("First user created successfully.")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating the first user: {e}")

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')