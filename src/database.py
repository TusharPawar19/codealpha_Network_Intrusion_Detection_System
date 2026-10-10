import sqlite3
import os
import logging
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DATABASE_PATH", "data/nids.db")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_connection():
    """Create and return a database connection."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_db():
    """Create the necessary tables if they don't exist."""
    logger.info(f"Initializing database at {DB_PATH}")
    conn = get_connection()
    cursor = conn.cursor()
    
    # Table for alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            proto TEXT,
            alert_signature TEXT NOT NULL,
            alert_category TEXT,
            alert_severity INTEGER,
            flow_id TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")

def insert_alert(alert_data):
    """Insert a single alert into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO alerts (
                timestamp, src_ip, src_port, dest_ip, dest_port, 
                proto, alert_signature, alert_category, alert_severity, flow_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data.get('timestamp'),
            alert_data.get('src_ip'),
            alert_data.get('src_port'),
            alert_data.get('dest_ip'),
            alert_data.get('dest_port'),
            alert_data.get('proto'),
            alert_data.get('alert', {}).get('signature', 'Unknown'),
            alert_data.get('alert', {}).get('category', 'Unknown'),
            alert_data.get('alert', {}).get('severity', 0),
            alert_data.get('flow_id')
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to insert alert: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    initialize_db()

