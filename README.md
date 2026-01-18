# watch-unlock-linux

Unlock your Linux PC with your Apple Watch, like macOS Auto Unlock.

## Features

- **Secure**: Uses IRK (Identity Resolving Key) to verify only YOUR Apple Watch
- **Fast**: Unlocks session within seconds of Watch detection
- **Auto-lock**: Optionally locks when Watch moves away
- **Systemd**: Runs as a background service

## How It Works

1. Scans for Bluetooth LE advertisements
2. Parses Apple Continuity Protocol (Nearby Info messages)
3. Verifies MAC address with your Watch's IRK
4. Detects `AUTO_UNLOCK_ON` flag (0x80) = Watch is unlocked
5. Unlocks session via `loginctl`

## Requirements

- Linux with BlueZ (tested on Ubuntu 24.04)
- Bluetooth LE adapter
- Python 3.10+ with `cryptography` package
- Apple Watch paired with iPhone (same iCloud as Mac)
- Mac with Auto Unlock enabled (to extract IRK)

## Installation

### 1. Clone and install

```bash
git clone https://github.com/DavidSt49/watch-unlock-linux.git
cd watch-unlock-linux
sudo ./install.sh
```

### 2. Get your Apple Watch IRK

On your Mac:
1. Open **Keychain Access** (Applications → Utilities)
2. Select **iCloud** in the left panel
3. Search for your Watch's Bluetooth address
4. Double-click, check "Show password"
5. Find `Remote IRK` in the XML (base64 encoded)
6. Decode and reverse:

```python
import base64
irk = base64.b64decode("YOUR_BASE64_IRK")[::-1]
print(irk.hex())  # Use this value
```

### 3. Configure

Edit `/etc/watch-unlock-linux/irk` (created by install) and replace the placeholder:
```
YOUR_IRK_HEX
```

The file is root-only; use `sudo` to edit.

> **Need help finding IRK?** See [ESPresense Apple Guide](https://espresense.com/devices/apple)

### 4. Test manually (recommended)

Before installing the service, test that everything works:

```bash
# Terminal 1: Start the daemon
sudo bash -c 'btmon -i hci0 | python3 /opt/watch-unlock-linux/unlock_daemon.py'

# Terminal 2: Enable BLE scanning
bluetoothctl
scan on
```

Then lock your session (Super+L) and unlock your Watch. If it works, proceed to install the service.

### 5. Start the service

```bash
sudo systemctl enable --now apple-watch-unlock
```

### 6. Check status

```bash
sudo systemctl status apple-watch-unlock
sudo journalctl -u apple-watch-unlock -f
```

## Configuration

IRK is read from `/etc/watch-unlock-linux/irk`. You can override with `WATCH_UNLOCK_LINUX_IRK` or `WATCH_UNLOCK_LINUX_IRK_FILE`.

In `/opt/watch-unlock-linux/unlock_daemon.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| `IRK_FILE` | `/etc/watch-unlock-linux/irk` | Path to IRK hex (or use `WATCH_UNLOCK_LINUX_IRK`) |
| `RSSI_UNLOCK_THRESHOLD` | -80 | Min signal strength to unlock |
| `RSSI_LOCK_THRESHOLD` | -85 | Lock when signal drops below |
| `ENABLE_AUTO_LOCK` | True | Auto-lock when Watch leaves |
| `LOCK_GRACE_PERIOD_SECONDS` | 30 | Seconds before auto-lock |
| `PRESENCE_TIMEOUT_SECONDS` | 60 | Lock if no signal for this long |

### Adjusting Thresholds

1. Run the debug script to see your RSSI values:
   ```bash
   sudo bash -c 'btmon -i hci0 | python3 /opt/watch-unlock-linux/debug_rssi.py'
   # + bluetoothctl scan on in another terminal
   ```

2. Note your RSSI when close (e.g., -70) and far (e.g., -90)

3. Edit `/opt/watch-unlock-linux/unlock_daemon.py`:
   ```python
   RSSI_UNLOCK_THRESHOLD = -75   # Adjust based on your "close" value
   RSSI_LOCK_THRESHOLD = -85     # Adjust based on your "far" value
   ```

4. Restart the service:
   ```bash
   sudo systemctl restart apple-watch-unlock
   ```

## Troubleshooting

**No detection**: Make sure `bluetoothctl scan on` is running

**Wrong IRK**: The IRK must be reversed from the base64 value in Keychain

**Weak signal**: Increase `RSSI_UNLOCK_THRESHOLD` (e.g., -90)

**Auto-lock not working**: Your RSSI may not drop low enough. Use `debug_rssi.py` to find the right threshold

## References

- [furiousMAC/continuity](https://github.com/furiousMAC/continuity) - Apple Continuity Protocol RE

## License

MIT
