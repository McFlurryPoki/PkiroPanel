#!/bin/bash
# TransetPanel Agent — 完整移除腳本
set -e

echo "============================================"
echo "  TransetPanel Agent Uninstaller"
echo "============================================"

# 1. Stop & disable services
echo "[1/4] Stopping services..."
systemctl stop realm-agent 2>/dev/null || true
systemctl stop realm 2>/dev/null || true
systemctl stop ss-rust 2>/dev/null || true
systemctl disable realm-agent 2>/dev/null || true
systemctl disable realm 2>/dev/null || true
systemctl disable ss-rust 2>/dev/null || true

# 2. Kill any running processes
echo "[2/4] Killing processes..."
pkill -f realm-agent.py 2>/dev/null || true
pkill -f /usr/local/bin/realm 2>/dev/null || true
pkill -f ssserver 2>/dev/null || true
sleep 1

# 3. Remove files
echo "[3/4] Removing files..."
rm -f /usr/local/bin/realm-agent.py
rm -f /usr/local/bin/realm
rm -f /usr/local/bin/ssserver
rm -f /usr/local/bin/sslocal
rm -f /usr/local/bin/ssurl
rm -f /usr/local/bin/ssmanager
rm -rf /etc/realm-panel
rm -f /etc/systemd/system/realm-agent.service
rm -f /etc/systemd/system/realm.service
rm -f /etc/systemd/system/ss-rust.service
rm -f /var/log/realm-agent.log
rm -f /var/log/realm.log

# 4. Reload systemd
echo "[4/4] Reloading systemd..."
systemctl daemon-reload 2>/dev/null || true

echo ""
echo "============================================"
echo "  移除完成！"
echo "============================================"
