#!/usr/bin/env python3
"""
Debug script to monitor RSSI values from your Apple Watch.
Shows every detection to help calibrate thresholds.

Usage:
    sudo btmon -i hci1 | sudo python3 debug_rssi.py
    # + bluetoothctl scan on in another terminal
"""

import sys
import re
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Your IRK - read from /etc/watch-unlock-linux/irk or WATCH_UNLOCK_LINUX_IRK
IRK_ENV_VAR = "WATCH_UNLOCK_LINUX_IRK"
IRK_FILE = os.environ.get("WATCH_UNLOCK_LINUX_IRK_FILE", "/etc/watch-unlock-linux/irk")

def parse_irk_hex(value: str, source: str) -> bytes:
    hex_str = value.strip().replace(" ", "").replace(":", "")
    if not hex_str:
        print(f"ERROR: Empty IRK in {source}")
        sys.exit(1)
    try:
        irk = bytes.fromhex(hex_str)
    except ValueError:
        print(f"ERROR: Invalid IRK hex in {source}")
        sys.exit(1)
    if len(irk) != 16:
        print(f"ERROR: Invalid IRK length in {source}: expected 16 bytes, got {len(irk)}")
        sys.exit(1)
    return irk

def load_irk() -> bytes:
    env_value = os.environ.get(IRK_ENV_VAR)
    if env_value:
        return parse_irk_hex(env_value, f"env:{IRK_ENV_VAR}")

    try:
        with open(IRK_FILE, "r", encoding="ascii") as handle:
            value = handle.read().strip()
    except FileNotFoundError:
        print(f"ERROR: IRK file not found at {IRK_FILE}. Set {IRK_ENV_VAR} or create the file.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to read IRK file {IRK_FILE}: {e}")
        sys.exit(1)
    return parse_irk_hex(value, f"file:{IRK_FILE}")

IRK = load_irk()

# Thresholds (same as daemon)
RSSI_UNLOCK_THRESHOLD = -80
RSSI_LOCK_THRESHOLD = -85

def ah(irk, prand):
    r_padded = bytes(13) + prand
    cipher = Cipher(algorithms.AES(irk), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return (enc.update(r_padded) + enc.finalize())[-3:]

def is_my_watch(mac_str):
    try:
        mac = bytes.fromhex(mac_str.replace(":", ""))
        if (mac[0] >> 6) != 0b01:
            return False
        return mac[3:6] == ah(IRK, mac[0:3])
    except:
        return False

print("=" * 60)
print("RSSI DEBUG MONITOR")
print("=" * 60)
print(f"Unlock threshold: {RSSI_UNLOCK_THRESHOLD} dBm")
print(f"Lock threshold:   {RSSI_LOCK_THRESHOLD} dBm")
print("=" * 60)
print()
print("Waiting for your Apple Watch...")
print("Move around to see RSSI changes.")
print()

mac = rssi = None
last_rssi = None

for line in sys.stdin:
    m = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', line)
    if m:
        mac = m.group(1)
    
    r = re.search(r'RSSI:\s*(-?\d+)', line)
    if r:
        rssi = int(r.group(1))
    
    hx = re.search(r'4c 00 10 (0[56]) ([0-9a-f]{2}) ([0-9a-f]{2})', line.lower())
    if hx and mac and rssi is not None and is_my_watch(mac):
        status_flags = int(hx.group(3), 16)
        is_unlocked = bool(status_flags & 0x80) and not bool(status_flags & 0x20)
        
        now = datetime.now().strftime("%H:%M:%S")
        
        if rssi >= RSSI_UNLOCK_THRESHOLD:
            zone = "UNLOCK ZONE"
            color = "\033[92m"
        elif rssi >= RSSI_LOCK_THRESHOLD:
            zone = "GRAY ZONE  "
            color = "\033[93m"
        else:
            zone = "LOCK ZONE  "
            color = "\033[91m"
        
        delta = ""
        if last_rssi is not None:
            diff = rssi - last_rssi
            if diff > 0:
                delta = f"(+{diff})"
            elif diff < 0:
                delta = f"({diff})"
        
        status = "unlocked" if is_unlocked else "locked"
        
        print(f"{color}[{now}] RSSI: {rssi:4} dBm {delta:6} | {zone} | Watch: {status}\033[0m")
        
        last_rssi = rssi
        mac = rssi = None
