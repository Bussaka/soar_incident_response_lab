#!/usr/bin/env python3
"""
SOAR Project - Phase 1/2: The Sensor
--------------------------------------
Watches the live systemd journal for the SSH service, detects brute-force
login patterns (N failed attempts from the same source IP within a time
window), and fires a JSON payload to an n8n webhook when the threshold
is crossed.

Run this on the target VM (the box being attacked).
"""

import json
import re
import subprocess
import time
import requests
from collections import defaultdict
from datetime import datetime

# --------------------------------------------------------------------------
# CONFIGURATION - adjust these to tune detection sensitivity
# --------------------------------------------------------------------------
FAILED_ATTEMPTS_THRESHOLD = 5      # number of failed logins to trigger an alert
TIME_WINDOW_SECONDS = 10           # within this many seconds
N8N_WEBHOOK_URL = "http://192.168.56.1:5678/webhook/ssh-bruteforce"  # update path once webhook node is created in n8n
COOLDOWN_SECONDS = 60              # don't re-alert on the same IP within this window

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)

failed_attempts = defaultdict(list)
last_alerted = {}


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")


def send_alert(ip: str, user: str, attempt_count: int) -> None:
    payload = {
        "event_type": "ssh_bruteforce_detected",
        "source_ip": ip,
        "target_user": user,
        "attempt_count": attempt_count,
        "window_seconds": TIME_WINDOW_SECONDS,
        "detected_at": datetime.utcnow().isoformat() + "Z",
        "hostname": subprocess.run(
            ["hostname"], capture_output=True, text=True
        ).stdout.strip(),
    }

    try:
        response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=5)
        log(f"ALERT SENT -> {ip} ({attempt_count} attempts) | n8n responded {response.status_code}")
    except requests.exceptions.RequestException as e:
        log(f"ERROR sending webhook for {ip}: {e}")


def prune_old_attempts(ip: str, now: float) -> None:
    failed_attempts[ip] = [
        t for t in failed_attempts[ip] if now - t <= TIME_WINDOW_SECONDS
    ]


def handle_failed_login(user: str, ip: str) -> None:
    now = time.time()
    failed_attempts[ip].append(now)
    prune_old_attempts(ip, now)

    count = len(failed_attempts[ip])
    log(f"Failed login for '{user}' from {ip} (count in window: {count})")

    if count >= FAILED_ATTEMPTS_THRESHOLD:
        last_alert_time = last_alerted.get(ip, 0)
        if now - last_alert_time >= COOLDOWN_SECONDS:
            send_alert(ip, user, count)
            last_alerted[ip] = now
        else:
            log(f"Threshold crossed for {ip} but within cooldown - suppressing duplicate alert")


def watch_journal() -> None:
    log("Sensor starting up. Watching journalctl -u ssh for brute-force patterns...")
    log(f"Threshold: {FAILED_ATTEMPTS_THRESHOLD} failed attempts within {TIME_WINDOW_SECONDS}s triggers an alert.")
    log(f"Webhook target: {N8N_WEBHOOK_URL}")

    cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0", "--no-pager"]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )

    try:
        for line in process.stdout:
            line = line.strip()
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                handle_failed_login(match.group("user"), match.group("ip"))
    except KeyboardInterrupt:
        log("Sensor stopped by user.")
    finally:
        process.terminate()


if __name__ == "__main__":
    watch_journal()