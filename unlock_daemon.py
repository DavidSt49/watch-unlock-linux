#!/usr/bin/env python3
"""
Apple Watch Unlock Daemon for Linux
====================================

Unlocks your Linux session when your Apple Watch is detected nearby and unlocked.

Features:
- IRK verification (only YOUR Watch)
- Status flag detection (AUTO_UNLOCK_ON)
- RSSI proximity check
- Auto-lock when Watch moves away (optional)
- Systemd service integration

Usage:
    sudo ./unlock_daemon.py

Or as a service:
    sudo systemctl enable --now apple-watch-unlock
"""

import sys
import re
import subprocess
import logging
import os
import select
from datetime import datetime
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ============================================================
# CONFIGURATION
# ============================================================

# Your Apple Watch IRK (from macOS Keychain)
IRK_ENV_VAR = "WATCH_UNLOCK_LINUX_IRK"
IRK_FILE = os.environ.get("WATCH_UNLOCK_LINUX_IRK_FILE", "/etc/watch-unlock-linux/irk")
IRK_SOURCE: Optional[str] = None
IRK: Optional[bytes] = None

# RSSI thresholds (adjust based on your environment)
# Your data: close=-66, far=-90
RSSI_UNLOCK_THRESHOLD = -80   # Must be closer than this to unlock
RSSI_LOCK_THRESHOLD = -85     # Lock when Watch is farther than this

# Status flags
FLAG_WATCH_LOCKED = 0x20
FLAG_AUTO_UNLOCK_ON = 0x80

# Timing
UNLOCK_DEBOUNCE_SECONDS = 0        # React immediately to unlock signal
LOCK_GRACE_PERIOD_SECONDS = 30    # Seconds before locking when Watch moves away
PRESENCE_TIMEOUT_SECONDS = 60     # Lock if no Watch signal for this long

# Features
ENABLE_AUTO_LOCK = True           # Lock when Watch moves away

# Logging
LOG_FILE = "/var/log/apple-watch-unlock.log"
LOG_LEVEL = logging.INFO

# ============================================================
# Setup Logging
# ============================================================

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr),
        # logging.FileHandler(LOG_FILE),  # Uncomment when running as service
    ]
)
log = logging.getLogger(__name__)

# ============================================================
# IRK Verification
# ============================================================

def parse_irk_hex(value: str, source: str) -> Optional[bytes]:
    hex_str = value.strip().replace(" ", "").replace(":", "")
    if not hex_str:
        log.error("Empty IRK in %s", source)
        return None
    try:
        irk = bytes.fromhex(hex_str)
    except ValueError:
        log.error("Invalid IRK hex in %s", source)
        return None
    if len(irk) != 16:
        log.error("Invalid IRK length in %s: expected 16 bytes, got %d", source, len(irk))
        return None
    return irk

def load_irk() -> Optional[bytes]:
    global IRK_SOURCE
    env_value = os.environ.get(IRK_ENV_VAR)
    if env_value:
        IRK_SOURCE = f"env:{IRK_ENV_VAR}"
        return parse_irk_hex(env_value, IRK_SOURCE)

    try:
        with open(IRK_FILE, "r", encoding="ascii") as handle:
            value = handle.read().strip()
    except FileNotFoundError:
        log.error("IRK file not found at %s; set %s or create the file.", IRK_FILE, IRK_ENV_VAR)
        return None
    except Exception as e:
        log.error("Failed to read IRK file %s: %s", IRK_FILE, e)
        return None

    IRK_SOURCE = f"file:{IRK_FILE}"
    return parse_irk_hex(value, IRK_SOURCE)

def ah(irk: bytes, prand: bytes) -> bytes:
    """Bluetooth address hash function."""
    r_padded = bytes(13) + prand
    cipher = Cipher(algorithms.AES(irk), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    return (enc.update(r_padded) + enc.finalize())[-3:]

def is_my_watch(mac_str: str) -> bool:
    """Verify MAC address belongs to MY Watch using IRK."""
    try:
        if not IRK:
            return False
        mac = bytes.fromhex(mac_str.replace(":", ""))
        if (mac[0] >> 6) != 0b01:
            return False
        return mac[3:6] == ah(IRK, mac[0:3])
    except:
        return False

# ============================================================
# Session Control
# ============================================================

def list_sessions() -> list[tuple[str, Optional[str]]]:
    """Return list of (session_id, seat) tuples."""
    try:
        result = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True, text=True, check=True
        )
    except Exception as e:
        log.error("Failed to list sessions: %s", e)
        return []

    sessions = []
    for line in result.stdout.strip().split('\n'):
        parts = line.split()
        if not parts:
            continue
        session_id = parts[0]
        seat = parts[3] if len(parts) >= 4 else None
        sessions.append((session_id, seat))
    return sessions

def list_seats() -> list[str]:
    """Return list of seat names."""
    try:
        result = subprocess.run(
            ["loginctl", "list-seats", "--no-legend"],
            capture_output=True, text=True, check=True
        )
    except Exception as e:
        log.debug("Failed to list seats: %s", e)
        return []

    seats = []
    for line in result.stdout.strip().split('\n'):
        parts = line.split()
        if parts:
            seats.append(parts[0])
    return seats

def get_active_session_for_seat(seat: str) -> Optional[str]:
    """Return active session id for a seat, if available."""
    try:
        result = subprocess.run(
            ["loginctl", "show-seat", seat, "-p", "ActiveSession"],
            capture_output=True, text=True, check=True
        )
    except Exception as e:
        log.debug("Failed to query seat %s: %s", seat, e)
        return None

    value = result.stdout.strip().split("=", 1)[-1]
    if value and value != "n/a":
        return value
    return None

def get_active_session_id() -> Optional[str]:
    seats = list_seats()
    if not seats:
        seats = ["seat0"]
    for seat in seats:
        session_id = get_active_session_for_seat(seat)
        if session_id:
            return session_id
    return None

def get_session_id() -> Optional[str]:
    """Get current user's login session ID."""
    session_id = get_active_session_id()
    if session_id:
        return session_id

    sessions = list_sessions()
    for session_id, seat in sessions:
        if seat and seat != "-":
            return session_id
    if sessions:
        return sessions[0][0]
    return None

def is_session_locked() -> bool:
    """Check if the current session is locked."""
    try:
        session_id = get_session_id()
        if not session_id:
            return False
        result = subprocess.run(
            ["loginctl", "show-session", session_id, "-p", "LockedHint"],
            capture_output=True, text=True, check=True
        )
        return "LockedHint=yes" in result.stdout
    except Exception as e:
        log.error(f"Failed to check lock state: {e}")
        return False

def unlock_session():
    """Unlock the current session."""
    try:
        session_id = get_session_id()
        if not session_id:
            log.error("No session ID found")
            return False
        
        log.info(f"[UNLOCK] Session {session_id} unlocked via Apple Watch")
        subprocess.run(
            ["loginctl", "unlock-session", session_id],
            check=True
        )
        return True
    except Exception as e:
        log.error(f"Failed to unlock session: {e}")
        return False

def lock_session():
    """Lock the current session."""
    try:
        session_id = get_session_id()
        if not session_id:
            return False
        
        log.info(f"[LOCK] Session {session_id} locked")
        subprocess.run(
            ["loginctl", "lock-session", session_id],
            check=True
        )
        return True
    except Exception as e:
        log.error(f"Failed to lock session: {e}")
        return False

# ============================================================
# State Machine
# ============================================================

class WatchState:
    def __init__(self):
        self.last_seen: Optional[datetime] = None
        self.last_rssi: Optional[int] = None
        self.last_unlock_time: Optional[datetime] = None
        self.leaving_since: Optional[datetime] = None
        self.auto_lock_paused: bool = True  # Start paused until we see the watch
        self.last_flags: Optional[int] = None

state = WatchState()

def handle_watch_detection(rssi: int, status_flags: int):
    global state
    now = datetime.now()
    
    if state.auto_lock_paused:
        log.info("[RESUME] Watch signal detected, auto-lock monitoring active")
        state.auto_lock_paused = False
    
    state.last_seen = now
    state.last_rssi = rssi
    state.last_flags = status_flags
    
    has_au_on = bool(status_flags & FLAG_AUTO_UNLOCK_ON)
    has_locked = bool(status_flags & FLAG_WATCH_LOCKED)
    is_on_wrist = has_au_on or has_locked
    
    if not is_on_wrist:
        state.leaving_since = None
        return
    
    if has_au_on and not has_locked and rssi >= RSSI_UNLOCK_THRESHOLD:
        state.leaving_since = None
        if is_session_locked():
            if state.last_unlock_time is None or \
               (now - state.last_unlock_time).seconds >= UNLOCK_DEBOUNCE_SECONDS:
                if unlock_session():
                    state.last_unlock_time = now
        return
    
    if ENABLE_AUTO_LOCK and is_on_wrist and rssi < RSSI_LOCK_THRESHOLD:
        if state.leaving_since is None:
            state.leaving_since = now
            status = "unlocked" if has_au_on else "locked"
            log.info(f"[AWAY] Watch on wrist ({status}) and far (RSSI: {rssi}), grace period started")
        elif (now - state.leaving_since).seconds >= LOCK_GRACE_PERIOD_SECONDS:
            if not is_session_locked():
                log.info(f"[LOCK] Auto-locking session (RSSI: {rssi})")
                lock_session()
                state.leaving_since = None
        return
    
    if rssi >= RSSI_LOCK_THRESHOLD and state.leaving_since is not None:
        log.info(f"[RETURN] Watch returned (RSSI: {rssi}), cancelling lock")
        state.leaving_since = None

def check_presence_timeout():
    """Pause auto-lock if Watch hasn't been seen for a while (watch probably off/stored)."""
    if not ENABLE_AUTO_LOCK or state.last_seen is None:
        return
    
    if state.auto_lock_paused:
        return  # Already paused
    
    elapsed = (datetime.now() - state.last_seen).seconds
    if elapsed >= PRESENCE_TIMEOUT_SECONDS:
        log.info(f"[PAUSE] Watch not seen for {elapsed}s, pausing auto-lock (watch probably off)")
        state.auto_lock_paused = True
        state.leaving_since = None  # Don't lock, just pause

# ============================================================
# Startup
# ============================================================

def print_startup_info():
    log.info("Apple Watch Unlock Daemon started")
    if IRK_SOURCE:
        log.info(f"  IRK source: {IRK_SOURCE}")
    else:
        log.info("  IRK source: unknown")
    log.info(f"  Unlock threshold: {RSSI_UNLOCK_THRESHOLD} dBm")
    log.info(f"  Lock threshold: {RSSI_LOCK_THRESHOLD} dBm")
    log.info(f"  Auto-lock: {'enabled' if ENABLE_AUTO_LOCK else 'disabled'}")

# ============================================================
# Main Loop
# ============================================================

def main():
    global IRK
    IRK = load_irk()
    if not IRK:
        log.error("IRK is not configured; exiting.")
        return 1

    print_startup_info()
    log.info("Waiting for Apple Watch...")
    
    mac = rssi = None
    
    try:
        while True:
            ready, _, _ = select.select([sys.stdin], [], [], 1.0)
            if ready:
                line = sys.stdin.readline()
                if not line:
                    break

                # Extract MAC
                m = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', line)
                if m:
                    mac = m.group(1)
                
                # Extract RSSI
                r = re.search(r'RSSI:\s*(-?\d+)', line)
                if r:
                    rssi = int(r.group(1))
                
                # Parse Nearby Info
                hx = re.search(r'4c 00 10 (0[56]) ([0-9a-f]{2}) ([0-9a-f]{2})', line.lower())
                if hx and mac and rssi is not None:
                    status_flags = int(hx.group(3), 16)
                    
                    if is_my_watch(mac):
                        has_au_on = bool(status_flags & FLAG_AUTO_UNLOCK_ON)
                        has_locked = bool(status_flags & FLAG_WATCH_LOCKED)
                        
                        if has_au_on and not has_locked:
                            status = "on-wrist/unlocked"
                        elif has_locked:
                            status = "on-wrist/locked"
                        else:
                            status = "off-wrist"
                        
                        log.debug(f"[DETECT] Watch {mac} | RSSI:{rssi} | {status} | flags:0x{status_flags:02X}")
                        
                        handle_watch_detection(rssi, status_flags)
                    
                    mac = rssi = None
            
            # Periodic presence check
            check_presence_timeout()
    
    except KeyboardInterrupt:
        log.info("Daemon stopped by user")
    except Exception as e:
        log.error(f"Daemon error: {e}")
        raise
    return 0

if __name__ == "__main__":
    sys.exit(main())
