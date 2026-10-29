# SNI Browser

**Single-binary browser with built-in SNI spoofing.** All HTTPS traffic is
routed through an embedded forward proxy that rewrites the TLS SNI
(Server Name Indication) to evade SNI-based censorship — the same technique
used by the iBoss/DPI evasion mitmproxy addon, now packaged as a standalone
browser with no external dependencies.

## How it works

```
┌────────────────────────────────────┐
│        SNI Browser (Go binary)     │
│                                    │
│  ┌──────────┐    ┌──────────────┐  │
│  │ WebView  │───▶│ Local Proxy  │  │
│  │ (system  │    │ 127.0.0.1:N  │  │
│  │ WebView) │    │              │  │
│  └──────────┘    │ SNI rewrite  │  │
│                  │ ↓            │  │
│                  │ TLS to host  │──┼──▶ Internet
│                  │ with fake SNI│  │
│                  └──────────────┘  │
└────────────────────────────────────┘
```

1. The browser starts an **embedded forward proxy** on a random localhost port.
2. The **WebView engine** (Edge WebView2 on Windows, WebKitGTK on Linux) is
   configured to route all traffic through this proxy.
3. For **HTTP requests**: forwarded normally.
4. For **HTTPS CONNECT tunnels**: the proxy establishes the upstream TLS
   connection with a **spoofed SNI** (e.g. `www.google.com` instead of
   `youtube.com`), then relays bytes transparently. No MITM certificates
   needed — TLS stays end-to-end.

## Evasion rules

Ported from the iBoss unblock mitmproxy addon (`iboss_unblock_addon.py`):

| Blocked domain | Spoofed SNI | Notes |
|---|---|---|
| `wordpress.com` | `en.wordpress.com` | |
| `gemini.google.com` | `www.google.com` | |
| `youtube.com` / `youtu.be` | `www.google.com` | Relaxed cert check |
| `ytimg.com` | `www.google.com` | Relaxed cert check |
| `googlevideo.com` | `www.google.com` | Relaxed cert check |
| `reddit.com` / `redd.it` / etc. | `alb.reddit.com` | Pinned IP: `151.101.1.140` |
| `crates.io` | `alb.reddit.com` | Relaxed cert check |

Edit `rules.go` to add more evasion rules.

## Build

### Linux (native)
```bash
# Requires: libwebkit2gtk-4.1-dev libgtk-3-dev
./build.sh linux
```

### Windows (cross-compile from Linux)
```bash
# Requires: mingw-w64-x86-64-dev
./build.sh windows
```

### Both
```bash
./build.sh all
```

## Usage

### Linux
```bash
./sni-browser-linux-amd64
```

### Windows
```cmd
sni-browser-windows-amd64.exe
```

**Keyboard shortcuts:**
- `Ctrl+L` — Open URL bar
- `Alt+←` — Back
- `Alt+→` — Forward
- `F5` / `Ctrl+R` — Refresh
- `Esc` — Close URL bar

A small **🔒 SNI** indicator in the URL bar confirms that traffic is routing
through the spoofing proxy.

## How it compares to the original tools

| Feature | snishield.py | mitmproxy + addon | SNI Browser |
|---|---|---|---|
| SNI fragmentation | ✅ | ❌ | ❌ |
| SNI rewriting | ❌ | ✅ | ✅ |
| Standalone (no Python/mitmproxy) | ❌ | ❌ | ✅ |
| Single binary | ❌ | ❌ | ✅ |
| Cross-platform | ❌ | ❌ | ✅ (Win + Linux) |
| Full browser GUI | ❌ | ❌ | ✅ |

## Requirements

- **Linux**: WebKit2GTK (`libwebkit2gtk-4.1-0`) — installed by default on most
  desktop distros.
- **Windows**: WebView2 runtime — pre-installed on Windows 10 (1809+) and
  Windows 11. If missing, download from
  [developer.microsoft.com/microsoft-edge/webview2](https://developer.microsoft.com/microsoft-edge/webview2/).

## License

MIT