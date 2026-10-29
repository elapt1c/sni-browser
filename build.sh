#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

BINARY="sni-browser"
LDFLAGS="-s -w"
# Shim so Debian 13's webkit2gtk-4.1 satisfies the library's webkit2gtk-4.0 requirement.
export PKG_CONFIG_PATH="$(pwd)/pkgconfig:${PKG_CONFIG_PATH:-}"
# Minimal EventToken.h shim (Windows SDK header MinGW doesn't ship).
export CGO_CXXFLAGS="-I$(pwd)/winsdk ${CGO_CXXFLAGS:-}"

echo "=== Building SNI Browser ==="

case "${1:-linux}" in
    linux)
        echo "→ Building for Linux amd64..."
        CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
            go build -ldflags "$LDFLAGS" -o "${BINARY}-linux-amd64" .
        echo "  → Built: ${BINARY}-linux-amd64"
        ls -lh "${BINARY}-linux-amd64"
        ;;
    windows)
        echo "→ Building for Windows amd64..."
        CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
            CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
            go build -ldflags "$LDFLAGS -H=windowsgui" -o "${BINARY}-windows-amd64.exe" .
        echo "  → Built: ${BINARY}-windows-amd64.exe"
        ls -lh "${BINARY}-windows-amd64.exe"
        ;;
    windows-console)
        echo "→ Building for Windows amd64 (console, for debugging)..."
        CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
            CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
            go build -ldflags "$LDFLAGS" -o "${BINARY}-windows-console.exe" .
        echo "  → Built: ${BINARY}-windows-console.exe"
        ls -lh "${BINARY}-windows-console.exe"
        ;;
    all)
        bash "$0" linux
        bash "$0" windows
        ;;
    *)
        echo "Usage: $0 {linux|windows|windows-console|all}"
        exit 1
        ;;
esac