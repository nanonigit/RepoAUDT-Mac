#!/bin/bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="RepoAUDT Mac"
BUNDLE_DIR="$DIR/$APP_NAME.app"
MODE="${1:---install}"

if [[ "$MODE" != "--install" && "$MODE" != "--no-install" ]]; then
    echo "usage: $0 [--install|--no-install]" >&2
    exit 2
fi

mkdir -p "$DIR/build"

# Clean up app bundles from repository root and legacy apps from /Applications
rm -rf "$DIR/$APP_NAME.app"
for legacy in "RepoPulse" "RepoChecker" "RepoChex"; do
    rm -rf "$DIR/$legacy.app"
    rm -rf "/Applications/$legacy.app" 2>/dev/null || true
done

STAGE="$(mktemp -d "$DIR/build/stage.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

APP="$STAGE/$APP_NAME.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "[1/4] Compiling Swift native macOS binary..."
swiftc -O -parse-as-library -target arm64-apple-macos14.0 \
    -framework SwiftUI -framework AppKit -framework WebKit -framework Combine -framework UserNotifications \
    "$DIR"/Sources/*.swift -o "$APP/Contents/MacOS/$APP_NAME"

echo "[2/4] Bundling Info.plist, AppIcon.icns, backend analyzer engine, and WebUI resources..."
cp "$DIR/Info.plist" "$APP/Contents/Info.plist"
if [[ -f "$DIR/AppIcon.icns" ]]; then
    cp "$DIR/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
fi
ditto "$DIR/Resources/backend" "$APP/Contents/Resources/backend"
ditto "$DIR/Resources/webui" "$APP/Contents/Resources/webui"
chmod +x "$APP/Contents/Resources/backend/server.py" "$APP/Contents/Resources/backend/analyzer.py" "$APP/Contents/Resources/backend/mcp_server.py"

echo "[3/4] Code-signing and verifying app bundle..."
codesign --force --deep --sign - "$APP"
codesign --verify --strict "$APP"

if [[ "$MODE" == "--install" ]]; then
    echo "[4/4] Installing to /Applications/$APP_NAME.app..."
    # Terminate running instances of current and legacy apps
    pkill -x "$APP_NAME" 2>/dev/null || true
    for legacy in "RepoPulse" "RepoChecker" "RepoChex"; do
        pkill -x "$legacy" 2>/dev/null || true
        rm -rf "/Applications/$legacy.app"
    done
    pkill -f "Resources/backend/server.py" 2>/dev/null || true
    for attempt in {1..30}; do
        if ! pgrep -x "$APP_NAME" >/dev/null; then break; fi
        sleep 0.1
    done
    rm -rf "/Applications/$APP_NAME.app"
    ditto "$APP" "/Applications/$APP_NAME.app"
    touch "/Applications/$APP_NAME.app"
    # Ensure repository root is cleaned so Spotlight and Raycast ONLY show /Applications/RepoAUDT Mac.app
    rm -rf "$DIR/$APP_NAME.app"
    echo "✅ Cleaned up old apps and installed: /Applications/$APP_NAME.app"
    echo "✨ (Repository root cleaned so only /Applications/$APP_NAME.app appears in Spotlight/Raycast)"
else
    rm -rf "$BUNDLE_DIR"
    ditto "$APP" "$BUNDLE_DIR"
    echo "✅ Built: $BUNDLE_DIR"
fi

