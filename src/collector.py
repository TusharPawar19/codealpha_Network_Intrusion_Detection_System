import json
import os
import time
import logging
from dotenv import load_dotenv
import database as db

load_dotenv()

EVE_LOG_PATH = os.getenv("SURICATA_EVE_LOG_PATH", "suricata/eve.json")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def process_log_file(file_path):
    """Read a Suricata eve.json file and insert alerts into the database."""
    if not os.path.exists(file_path):
        logger.warning(f"Log file not found: {file_path}")
        return

    logger.info(f"Processing log file: {file_path}")
    db.initialize_db()
    
    count = 0
    try:
        with open(file_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # We are only interested in 'alert' events
                    if data.get('event_type') == 'alert':
                        db.insert_alert(data)
                        count += 1
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON line: {line.strip()}")
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        
    logger.info(f"Processed {count} alerts from {file_path}")

def watch_log_file(file_path):
    """Tail the log file in real-time (basic implementation)."""
    if not os.path.exists(file_path):
        logger.error(f"Log file {file_path} does not exist. Please create it or wait for Suricata.")
        return

    logger.info(f"Watching log file {file_path} for new alerts...")
    db.initialize_db()
    
    with open(file_path, 'r') as f:
        # Move to the end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            try:
                data = json.loads(line)
                if data.get('event_type') == 'alert':
                    db.insert_alert(data)
                    logger.info(f"New alert processed: {data.get('alert', {}).get('signature')}")
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Suricata EVE Log Collector")
    parser.add_argument("--watch", action="store_true", help="Watch file continuously")
    args = parser.parse_args()
    
    if args.watch:
        watch_log_file(EVE_LOG_PATH)
    else:
        process_log_file(EVE_LOG_PATH)
