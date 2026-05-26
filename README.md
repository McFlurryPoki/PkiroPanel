# PkiroPanel

基於 [gost](https://github.com/go-gost/gost)、[WireGuard](https://www.wireguard.com/)、[sing-box](https://github.com/SagiNet/sing-box) 等開源項目構建的多協議轉發與多節點管理面板。

## Features

- **Multi-node management**: Entry, transit, and landing node orchestration
- **Tunnel forwarding**: TLS, mTLS, and **WireGuard** tunnel support
- **Gost integration**: gost v3 (YAML-based) forwarding engine
- **sing-box support**: Inbound proxy management
- **Traffic monitoring**: Per-node and per-forward traffic tracking
- **Subscription converter**: Parse and serve proxy subscriptions
- **WebSocket agents**: Real-time node status and command dispatch
- **Responsive UI**: Dark theme, salmon-red accent, optimized for desktop and mobile

## Quick Start

### Panel (Docker)

```bash
# 1. 解壓
tar xzf PkiroPanel-v27.05.2026a.tar.gz
cd PkiroPanel-v27.05.2026a/docker

# 2. 修改環境變數（可選）
nano .env
# SECRET_KEY= 改成你自己的隨機字串
# PANEL_URL= 改成你的公網位址（如 https://panel.example.com:443）

# 3. 啟動
docker compose up -d
```

預設登入：`admin` / `admin123`

### Agent（節點端）

在每個需要管理的節點上執行：

```bash
bash install.sh <PANEL_URL> <NODE_ID>
# 例：bash install.sh https://panel.example.com node-abc123
```

## Updating

```bash
# 1. 解壓新版
tar xzf PkiroPanel-vXX.XX.XXXXa.tar.gz

# 2. 覆蓋源碼
cp -a PkiroPanel-vXX.XX.XXXXa/panel .
cp PkiroPanel-vXX.XX.XXXXa/requirements.txt .

# 3. 單行重建
cd docker && docker compose down && docker compose up -d --build
```

## Architecture

```
Panel (Docker) ──WebSocket──▶ Agent (on each node)
                                  │
                                  ├── gost (forwarding engine)
                                  ├── sing-box (inbound proxy)
                                  └── WireGuard (tunnel transport)
```

## Requirements

- **Panel**: Docker + Docker Compose
- **Agent**: Python 3.8+, Linux with systemd

## License

MIT
