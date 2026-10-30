#!/usr/bin/env bash
set -euo pipefail
SERVER="${1:?Usage: install-agent.sh SERVER ENROLLMENT_TOKEN}"
TOKEN="${2:?Missing enrollment token}"
INTERVAL="${3:-60}"
DIR="/opt/congo-sec-vision-agent"
sudo mkdir -p "$DIR"
sudo cp "$(dirname "$0")/../agent/agent.py" "$DIR/agent.py"
sudo cp "$(dirname "$0")/../agent/requirements.txt" "$DIR/requirements.txt"
sudo python3 -m pip install -r "$DIR/requirements.txt"
sudo tee /etc/systemd/system/congo-sec-vision-agent.service >/dev/null <<EOF
[Unit]
Description=Congo Sec Vision authorized endpoint agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 $DIR/agent.py --server $SERVER --enrollment-token $TOKEN --interval $INTERVAL
Restart=always
RestartSec=10
User=root
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now congo-sec-vision-agent
