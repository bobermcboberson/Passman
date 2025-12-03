import MySQLdb
import os

def get_db_connection():
    try:
        conn = MySQLdb.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            passwd=os.getenv("DB_PASSWORD"),
            db=os.getenv("DB_NAME"),
            charset='utf8mb4'
        )
        return conn
    except MySQLdb.Error as e:
        print(f"Database connection failed: {e}")
        return None