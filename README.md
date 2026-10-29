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
│  └──────────┘    │ rewrite SNI  │  │
│                  │ in ClientHello│ │
│                  └──────┬───────┘  │
└─────────────────────────┼──────────┘
                          ▼
                     Internet (TLS stays end-to-end)
```

1. The browser starts an **embedded forward proxy** on a random localhost port.
2. The **WebView engine** (Edge WebView2 on Windows, WebKitGTK on Linux) is
   configured to route all traffic through this proxy.
3. For **HTTP requests**: forwarded normally.
4. For **HTTPS CONNECT tunnels**: the proxy is a transparent relay. When a
   rule matches, it rewrites the SNI **inside the client's TLS ClientHello**
   before the bytes reach the server (e.g. `wordpress.com` → `en.wordpress.com`).
   No MITM certificates and no proxy-side TLS — the TLS session remains
   end-to-end between the browser and the origin server.

## Important limitation

Because TLS stays end-to-end (no MITM), the browser still validates the
origin's certificate against the **original** hostname. SNI rewriting therefore
only works when the origin serves a certificate that also covers the original
name — typically a **wildcard cert**:

- ✅ `wordpress.com` → `en.wordpress.com` (Automattic serves `*.wordpress.com`)
- ✅ `reddit.com` → `alb.reddit.com` (Fastly serves `*.reddit.com`)
- ❌ YouTube / Google CDN family (Google edges serve a fixed cert unrelated to
  the allowed SNI — needs a MITM CA to relax the name check)

The `Relaxed` flag in `rules.go` marks rules that need full MITM (not yet
implemented); those sites will show a certificate error with the transparent
approach.

## Evasion rules

Ported from the iBoss unblock mitmproxy addon (`iboss_unblock_addon.py`):

| Blocked domain | Spoofed SNI | Notes |
|---|---|---|
| `wordpress.com` | `en.wordpress.com` | works transparently |
| `gemini.google.com` | `www.google.com` | works transparently |
| `youtube.com` / `youtu.be` | `www.google.com` | needs MITM (cert mismatch) |
| `ytimg.com` | `www.google.com` | needs MITM (cert mismatch) |
| `googlevideo.com` | `www.google.com` | needs MITM (cert mismatch) |
| `reddit.com` / `redd.it` / etc. | `alb.reddit.com` | works transparently, pinned IP `151.101.1.140` |
| `crates.io` | `alb.reddit.com` | needs MITM (cert mismatch) |

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