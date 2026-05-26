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

```bash
# Install with default settings
bash install.sh

# Or for CN mirror (downloads from Chinese mirrors)
bash install-cn.sh
```

Default login: `admin` / `admin123`

## Architecture

```
Panel (Docker) ──WebSocket──▶ Agent (on each node)
                                  │
                                  ├── gost (forwarding engine)
                                  ├── sing-box (inbound proxy)
                                  └── WireGuard (tunnel transport)
```

## Requirements

- Docker (for panel)
- Python 3.8+ (for agents on nodes)
- Linux nodes with systemd

## License

MIT
