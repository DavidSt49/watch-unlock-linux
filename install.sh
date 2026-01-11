#!/bin/bash
# Install script for Watch Unlock Linux

set -e

INSTALL_DIR="/opt/watch-unlock-linux"
SERVICE_FILE="/etc/systemd/system/apple-watch-unlock.service"
CONFIG_DIR="/etc/watch-unlock-linux"
IRK_FILE="$CONFIG_DIR/irk"

echo "Watch Unlock Linux - Installer"
echo "==============================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./install.sh"
    exit 1
fi

# Check dependencies
echo "[1/6] Checking dependencies..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found. Install with: sudo apt install python3"
    exit 1
fi

if ! python3 -c "import cryptography" 2>/dev/null; then
    if command -v apt-get &> /dev/null; then
        echo "Installing python3-cryptography..."
        apt-get install -y python3-cryptography
    else
        echo "ERROR: python3-cryptography not found. Install it with your package manager."
        exit 1
    fi
fi

if ! command -v btmon &> /dev/null; then
    echo "ERROR: btmon not found. Install with: sudo apt install bluez"
    exit 1
fi

# Create install directory
echo "[2/6] Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp unlock_daemon.py "$INSTALL_DIR/"
cp debug_rssi.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/unlock_daemon.py" "$INSTALL_DIR/debug_rssi.py"

# Setup config
echo "[3/6] Setting up config..."
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
if [ ! -f "$IRK_FILE" ]; then
    echo "YOUR_IRK_HEX" > "$IRK_FILE"
fi
chmod 600 "$IRK_FILE"
chown root:root "$IRK_FILE"

# Install service
echo "[4/6] Installing systemd service..."
cp apple-watch-unlock.service "$SERVICE_FILE"

# Detect Bluetooth adapter
echo "[5/6] Detecting Bluetooth adapter..."
HCI_DEV=$(hciconfig | grep -o "hci[0-9]" | head -1)
if [ -z "$HCI_DEV" ]; then
    HCI_DEV="hci0"
    echo "WARNING: No Bluetooth adapter found, using $HCI_DEV"
else
    echo "Found: $HCI_DEV"
    sed -i "s/hci0/$HCI_DEV/g" "$SERVICE_FILE"
fi

# Reload systemd
echo "[6/6] Reloading systemd..."
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit $IRK_FILE"
echo "     Set your IRK hex value"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl enable --now apple-watch-unlock"
echo ""
echo "  3. Check status:"
echo "     sudo systemctl status apple-watch-unlock"
echo "     sudo journalctl -u apple-watch-unlock -f"
