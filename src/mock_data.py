import json
import os
import random
import time
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SIGNATURES = [
    {"signature": "[DEMO] ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2, "proto": "TCP", "port": 22},
    {"signature": "[DEMO] GPL ICMP_INFO PING *NIX", "category": "Misc activity", "severity": 3, "proto": "ICMP", "port": None},
    {"signature": "[DEMO] ET EXPLOIT Possible CVE-2021-44228 Log4j Attempt", "category": "Attempted Administrator Privilege Gain", "severity": 1, "proto": "TCP", "port": 8080},
    {"signature": "[DEMO] ET SCAN Nmap OS Detection Probe", "category": "Attempted Information Leak", "severity": 2, "proto": "TCP", "port": 80},
    {"signature": "[DEMO] ET MALWARE Suspicious DNS Query (randomized domain)", "category": "A Network Trojan was detected", "severity": 1, "proto": "UDP", "port": 53}
]

def generate_mock_alert(timestamp=None):
    if timestamp is None:
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"
        
    sig = random.choice(SIGNATURES)
    
    src_ip = f"192.168.1.{random.randint(100, 200)}"
    dest_ip = f"10.0.0.{random.randint(1, 20)}"
    
    src_port = random.randint(1024, 65535) if sig['proto'] != "ICMP" else None
    dest_port = sig['port'] if sig['port'] else random.randint(1024, 65535)
    
    return {
        "timestamp": timestamp,
        "flow_id": random.randint(1000000000000000, 9999999999999999),
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": sig['proto'],
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": sig['signature'],
            "category": sig['category'],
            "severity": sig['severity']
        }
    }

def generate_historical_data(file_path, count=50):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    logger.info(f"Generating {count} historical mock alerts to {file_path}")
    
    alerts = []
    now = datetime.utcnow()
    
    for i in range(count):
        # Go back in time up to 7 days
        time_diff = timedelta(hours=random.randint(0, 168), minutes=random.randint(0, 60))
        event_time = now - time_diff
        timestamp = event_time.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"
        alerts.append(generate_mock_alert(timestamp))
        
    # Sort by time
    alerts.sort(key=lambda x: x["timestamp"])
    
    with open(file_path, 'w') as f:
        for alert in alerts:
            f.write(json.dumps(alert) + '\n')
            
    logger.info("Historical data generation complete.")

def run_live_simulation(file_path, interval=5):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    logger.info(f"Starting live simulation. Writing to {file_path} every ~{interval} seconds.")
    
    try:
        with open(file_path, 'a') as f:
            while True:
                alert = generate_mock_alert()
                f.write(json.dumps(alert) + '\n')
                f.flush()
                logger.info(f"Generated alert: {alert['alert']['signature']}")
                
                # Add some randomness to the interval
                sleep_time = interval * (0.5 + random.random())
                time.sleep(sleep_time)
    except KeyboardInterrupt:
        logger.info("Simulation stopped.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate mock Suricata EVE logs")
    parser.add_argument("--file", default="suricata/eve.json", help="Output file path")
    parser.add_argument("--live", action="store_true", help="Run in live simulation mode")
    parser.add_argument("--count", type=int, default=50, help="Number of historical events to generate")
    
    args = parser.parse_args()
    
    if args.live:
        run_live_simulation(args.file)
    else:
        generate_historical_data(args.file, args.count)

