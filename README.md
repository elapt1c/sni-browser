# SNI Browser

**Single-binary browser with built-in SNI-spoofing MITM proxy.** Runs as a
real browser (URL bar, back/forward/reload buttons) and routes HTTPS through
an embedded proxy that rewrites the TLS SNI to bypass SNI-based censorship.
This is the same evasion used by the iBoss/DPI mitmproxy addon, packaged into
a self-contained browser with no external dependencies.

## How it works

```
┌─────────────────────────────────────────────┐
│            SNI Browser (Go binary)          │
│                                             │
│  ┌──────────────┐   ┌────────────────────┐  │
│  │ WebView +    │──▶│ Embedded MITM proxy│  │
│  │ toolbar UI   │   │ 127.0.0.1:N        │  │
│  └──────────────┘   │                    │  │
│                     │  blocked host:     │  │
│                     │  - serve CA leaf   │  │
│                     │    cert to browser │  │
│                     │  - upstream TLS    │  │
│                     │    with fake SNI   │  │
│                     └─────────┬──────────┘  │
└───────────────────────────────┼──────────────┘
                                ▼
                           Internet (upstream SNI is spoofed)
```

1. On first run the browser generates a **root CA** and installs it as trusted
   (current-user cert store on Windows, system trust store on Linux).
2. All traffic is routed through the embedded forward proxy.
3. For a **blocked host** (per `rules.go`), the proxy performs a TLS MITM:
   - serves the browser a certificate minted by the CA for the *real* hostname
     (so the browser sees a valid cert, e.g. `youtube.com`);
   - dials upstream with a **spoofed SNI** (e.g. `www.google.com`) while
     keeping the original HTTP `Host` header, so the CDN serves the real site.
4. For non-blocked hosts it relays transparently (no MITM).

This makes the whole evasion table work, including **YouTube** (the Google CDN
serves a fixed edge cert unrelated to the allowed SNI; the proxy validates the
chain but skips the upstream cert-name check for those rules).

## Browser chrome

- Persistent toolbar with **back / forward / reload / home** buttons and a
  **URL bar**.
- `Ctrl+L` focuses the URL bar; `Enter` navigates.
- The URL bar shows a **🔒 SNI** indicator.

## Evasion rules

Ported from the iBoss unblock mitmproxy addon (`iboss_unblock_addon.py`):

| Blocked domain | Spoofed SNI | Upstream cert check |
|---|---|---|
| `wordpress.com` | `en.wordpress.com` | strict |
| `gemini.google.com` | `www.google.com` | strict |
| `youtube.com` / `youtu.be` | `www.google.com` | relaxed |
| `ytimg.com` | `www.google.com` | relaxed |
| `googlevideo.com` | `www.google.com` | relaxed |
| `reddit.com` / `redd.it` / etc. | `alb.reddit.com` | strict, pinned IP `151.101.1.140` |
| `crates.io` | `alb.reddit.com` | relaxed |

Edit `rules.go` to add more rules.

## Build

### Linux (native)
```bash
# Requires: libwebkit2gtk-4.1-dev libgtk-3-dev
./build.sh linux
```

### Windows (cross-compile from Linux)
```bash
# Requires: mingw-w64
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
First run installs the CA into the system trust store (uses `sudo -n`; if that
fails it falls back to a per-process CA bundle).

### Windows
```cmd
sni-browser-windows-amd64.exe
```
First run installs the CA into the current user's cert store via `certutil`
(no admin needed). Requires the WebView2 runtime (preinstalled on Win10
1809+/Win11).

## Requirements

- **Linux**: WebKit2GTK (`libwebkit2gtk-4.1-0`), `sudo` (for CA install).
- **Windows**: WebView2 runtime.

## License

MIT