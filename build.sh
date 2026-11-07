#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="RepoPulse"
BUNDLE_DIR="$DIR/$APP_NAME.app"
MODE="${1:---install}"

if [[ "$MODE" != "--install" && "$MODE" != "--no-install" ]]; then
    echo "usage: $0 [--install|--no-install]" >&2
    exit 2
fi

mkdir -p "$DIR/build"
STAGE="$(mktemp -d "$DIR/build/stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

APP="$STAGE/$APP_NAME.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "[1/4] Compiling Swift native macOS binary..."
swiftc -O -parse-as-library -target arm64-apple-macos14.0 \
    -framework SwiftUI -framework AppKit -framework WebKit -framework Combine \
    "$DIR"/Sources/*.swift -o "$APP/Contents/MacOS/$APP_NAME"

echo "[2/4] Bundling Info.plist, backend analyzer engine, and WebUI resources..."
cp "$DIR/Info.plist" "$APP/Contents/Info.plist"
ditto "$DIR/Resources/backend" "$APP/Contents/Resources/backend"
ditto "$DIR/Resources/webui" "$APP/Contents/Resources/webui"
chmod +x "$APP/Contents/Resources/backend/server.py" "$APP/Contents/Resources/backend/analyzer.py"

echo "[3/4] Code-signing and verifying app bundle..."
codesign --force --deep --sign - "$APP"
codesign --verify --strict "$APP"

rm -rf "$BUNDLE_DIR"
ditto "$APP" "$BUNDLE_DIR"

if [[ "$MODE" == "--install" ]]; then
    echo "[4/4] Installing to /Applications/$APP_NAME.app..."
    pkill -x "$APP_NAME" 2>/dev/null || true
    for attempt in {1..30}; do
        if ! pgrep -x "$APP_NAME" >/dev/null; then break; fi
        sleep 0.1
    done
    rm -rf "/Applications/$APP_NAME.app"
    ditto "$BUNDLE_DIR" "/Applications/$APP_NAME.app"
    echo "✅ Installed: /Applications/$APP_NAME.app"
else
    echo "✅ Built: $BUNDLE_DIR"
fi
