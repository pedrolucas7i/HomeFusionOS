import os
import bcrypt
import logging
from models import db, User, WallpaperAndThemeForUser 

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
NOT_ALLOWED_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.sh', '.bin', '.msi', '.com', '.scr',
    '.php', '.py', '.pl', '.cgi', '.js', '.asp', '.jsp', '.rb',
    '.docm', '.xlsm', '.pptm', '.dll', '.so', '.dylib', '.lnk',
    '.ini', '.conf', '.sys', '.drv', '.inf', '.svg', '.ico'
}

def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    return os.path.splitext(filename)[1].lower() not in NOT_ALLOWED_EXTENSIONS

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(stored_password: str, provided_password: str) -> bool:
    """Check if the provided password matches the stored hashed password."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))

def log_user_access(user_id: int, access_level: str) -> None:
    """Log user access information."""
    logging.info(f"User  ID: {user_id} accessed with level: {access_level}")

def get_selected_wallpaper_and_theme(user_id: int) -> tuple[str, str]:
    """Get the selected wallpaper and theme for a user."""
    result = WallpaperAndThemeForUser .query.filter_by(user_id=user_id).order_by(WallpaperAndThemeForUser .applied_at.desc()).first()
    if result:
        return result.wallpaper_path, result.theme
    return "", ""

def get_all_users() -> list[User ]:
    """Retrieve all users from the database."""
    return User.query.all()

def create_user(username: str, password: str) -> None:
    """Create a new user in the database."""
    hashed_password = hash_password(password)
    new_user = User(username=username, password=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"User  '{username}' created successfully.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating user '{username}': {e}")

def delete_user(user_id: int) -> None:
    """Delete a user from the database."""
    user = User.query.get(user_id)
    if user:
        try:
            db.session.delete(user)
            db.session.commit()
            logging.info(f"User  ID: {user_id} deleted successfully.")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting user ID: {user_id}: {e}")

def update_user_password(user_id: int, new_password: str) -> None:
    """Update the password for a user."""
    user = User.query.get(user_id)
    if user:
        user.password = hash_password(new_password)
        try:
            db.session.commit()
            logging.info(f"Password for user ID: {user_id} updated successfully.")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating password for user ID: {user_id}: {e}")

def apply_wallpaper_and_theme(user_id: int, wallpaper_path: str, theme: str) -> None:
    """Apply a wallpaper and theme for a user."""
    new_entry = WallpaperAndThemeForUser (user_id=user_id, wallpaper_path=wallpaper_path, theme=theme)
    try:
        db.session.add(new_entry)
        db.session.commit()
        logging.info(f"Wallpaper and theme applied for user ID: {user_id}.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error applying wallpaper and theme for user ID: {user_id}: {e}")