# PkiroPanel

Multi-node proxy management panel with WireGuard tunnel support.

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

# 4. 確認運行
docker logs realm-panel
```

預設登入：`admin` / `admin123`

### Agent（節點端）

在每個需要管理的節點上執行：

```bash
bash install.sh <PANEL_URL> <NODE_ID>
# 例：bash install.sh https://panel.example.com node-abc123
```

## Updating

更新到新版時，解壓新版源碼後重建 Docker 映像：

```bash
# 1. 備份當前資料庫（重要！）
cp docker/data/realm_panel.db docker/data/realm_panel.db.bak.$(date +%Y%m%d_%H%M%S)

# 2. 解壓新版並覆蓋 panel/ 目錄
tar xzf PkiroPanel-vXX.XX.XXXXa.tar.gz
cp -a PkiroPanel-vXX.XX.XXXXa/panel/ panel/
cp PkiroPanel-vXX.XX.XXXXa/requirements.txt .

# 3. 停止、重建、啟動
cd docker
docker compose down
docker compose up -d --build
```

> ⚠️ **重建會丟失資料**
> `docker compose down` 會移除容器。雖然資料庫透過 volume `./data:/data` 掛載保存，但重建過程中仍建議**務必先備份** `docker/data/realm_panel.db`。
>
> 如需恢復備份：
> ```bash
> cp docker/data/realm_panel.db.bak.XXXXXXXX docker/data/realm_panel.db
> docker compose restart
> ```

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
