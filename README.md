# PkiroPanel

基於 [gost](https://github.com/go-gost/gost)、[WireGuard](https://www.wireguard.com/)、[sing-box](https://github.com/SagiNet/sing-box) 等開源項目構建的多協議轉發與多節點管理面板。

## 功能特色

- **多節點管理**：入口、中轉、落地節點統一編排
- **隧道轉發**：支援 TLS、mTLS 及 **WireGuard** 隧道
- **Gost 整合**：gost v3（YAML 設定）轉發引擎
- **sing-box 支援**：入站代理管理
- **流量監控**：按節點及轉發規則追蹤流量
- **訂閱轉換器**：解析並提供代理訂閱端點
- **WebSocket 代理**：即時節點狀態與指令派發
- **響應式介面**：深色主題、鮭魚紅點綴、桌面及手機端最佳化

## 快速開始

### 面板端（Docker）

```bash
# 1. 解壓
tar xzf PkiroPanel-v27.05.2026.tar.gz
cd PkiroPanel-v27.05.2026/docker

# 2. 修改環境變數（可選）
nano .env
# SECRET_KEY= 改成你自己的隨機字串
# PANEL_URL= 改成你的公網位址（如 https://panel.example.com:443）

# 3. 啟動
docker compose up -d
```

預設登入：`admin` / `admin123`

### 代理端（節點）

在面板中新增節點後，於對應伺服器上執行：

```bash
bash install.sh <PANEL_URL> <NODE_ID>
# 例：bash install.sh https://panel.example.com node-abc123
```

Agent 會根據面板設定的節點類型自動派發對應服務（入口/中轉 → gost＋WG、落地 → sing-box）。

## 版本更新

```bash
# 1. 解壓新版
tar xzf PkiroPanel-vXX.XX.XXXX.tar.gz

# 2. 覆蓋原始碼
cp -a PkiroPanel-vXX.XX.XXXX/panel .
cp PkiroPanel-vXX.XX.XXXX/requirements.txt .

# 3. 單行重建
cd docker && docker compose down && docker compose up -d --build
```

## 架構

`Panel(Docker) ←WebSocket→ Agent(節點) ─ gost/WG(入口/中轉) ─ sing-box(落地)`

## 環境需求

- **面板**：Docker + Docker Compose
- **代理**：Python 3.8+、Linux 且含 systemd

## 授權條款

MIT
