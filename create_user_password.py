import bcrypt
import mysql.connector
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()
USER_DB = os.getenv('USER_DB')
PASS_DB = os.getenv('PASS_DB')
DB = os.getenv('DB')

print(USER_DB)
print(PASS_DB)

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')  # Decode bytes to string for storage

def store_user(username, password):
    try:
        # Connect to the database
        conn = mysql.connector.connect(
            host="localhost",
            user=USER_DB,
            password=PASS_DB,
            database=DB
        )
        cursor = conn.cursor()
        
        # Hash the password
        hashed_password = hash_password(password)
        
        # Insert the user into the database
        query = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))
        
        # Commit the transaction
        conn.commit()
        
        print("User stored successfully.")
    
    except mysql.connector.Error as err:
        print(f"Error: {err}")
    
    finally:
        # Close the cursor and connection
        cursor.close()
        conn.close()

# Prompt user for password and store user
user = input("User:\t")
password = input("Password:\t")
store_user(user, password)
