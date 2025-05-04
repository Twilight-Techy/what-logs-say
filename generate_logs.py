#!/usr/bin/env python3

import argparse
import time
import random
from datetime import datetime, timedelta, timezone
from google.cloud import logging

def create_hacking_logs(count=100):
    """Generate realistic logs simulating external hacking attempt that eventually succeeds."""
    client = logging.Client()
    logger = client.logger("security-logs")
    
    # Realistic IP addresses for attackers
    attacker_ips = [
        "185.220.102.8",   # Known TOR exit node
        "103.28.247.135",  # Suspicious Asian IP
        "45.77.106.251",   # VPS provider
        "198.98.51.60",    # Another suspicious IP
        "192.158.29.74"    # More suspicious IP
    ]
    
    # Different stages of the attack
    log_entries = []
    current_time = datetime.now(timezone.utc)
    
    # Stage 1: Reconnaissance
    for i in range(20):
        log_entries.append({
            "timestamp": current_time - timedelta(minutes=random.randint(55, 60)),
            "severity": "WARNING",
            "message": f"Unusual port scan detected from {random.choice(attacker_ips)}, targeting ports 22, 80, 443, 3306"
        })
    
    # Stage 2: Initial access attempts
    for i in range(30):
        log_entries.append({
            "timestamp": current_time - timedelta(minutes=random.randint(40, 50)),
            "severity": "ERROR",
            "message": f"Failed login attempt from IP {attacker_ips[0]}: Invalid credentials for user admin"
        })
    
    # Stage 3: Successful breach
    log_entries.append({
        "timestamp": current_time - timedelta(minutes=35),
        "severity": "CRITICAL",
        "message": f"Multiple failed login attempts detected from {attacker_ips[0]}: Possible brute force attack"
    })
    
    log_entries.append({
        "timestamp": current_time - timedelta(minutes=30),
        "severity": "ERROR",
        "message": f"Successful login from unusual location: IP {attacker_ips[0]}, user: admin"
    })
    
    # Stage 4: Lateral movement
    for i in range(15):
        log_entries.append({
            "timestamp": current_time - timedelta(minutes=random.randint(20, 28)),
            "severity": "ERROR",
            "message": f"Suspicious command execution: 'cat /etc/passwd' from user admin, IP {attacker_ips[0]}"
        })
    
    # Stage 5: Data exfiltration
    log_entries.append({
        "timestamp": current_time - timedelta(minutes=15),
        "severity": "CRITICAL", 
        "message": f"Unusual outbound traffic volume (450MB) to IP {attacker_ips[0]}"
    })
    
    log_entries.append({
        "timestamp": current_time - timedelta(minutes=10),
        "severity": "CRITICAL",
        "message": f"Possible data exfiltration: Database dump command executed by user admin"
    })
    
    # Stage 6: Covering tracks
    log_entries.append({
        "timestamp": current_time - timedelta(minutes=5),
        "severity": "ERROR",
        "message": f"System logs cleared by user admin from IP {attacker_ips[0]}"
    })
    
    # Sort logs by timestamp
    log_entries.sort(key=lambda x: x["timestamp"])
    
    # Generate the logs
    for i, entry in enumerate(log_entries):
        if i >= count:
            break
            
        # Create proper structured log
        log_struct = {
            "timestamp": entry["timestamp"].isoformat(),
            "severity": entry["severity"],
            "message": entry["message"],
            "sourceIP": [ip for ip in attacker_ips if ip in entry["message"]][0] if any(ip in entry["message"] for ip in attacker_ips) else None,
            "eventType": "SECURITY_ALERT",
            "threatLevel": "HIGH" if entry["severity"] == "CRITICAL" else "MEDIUM"
        }
        
        logger.log_struct(log_struct, severity=entry["severity"])
        print(f"Created log: {entry['message']}")
        time.sleep(0.5)  # Delay to ensure different timestamps
    
    print(f"Created {min(count, len(log_entries))} hacking logs in project")
    print("Wait a minute or two for logs to be available in Cloud Logging")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate enhanced security logs")
    parser.add_argument("type", choices=["hacking"], help="Type of attack scenario to generate")
    parser.add_argument("--count", type=int, default=100, help="Number of logs to generate")
    
    args = parser.parse_args()
    
    if args.type == "hacking":
        create_hacking_logs(args.count)