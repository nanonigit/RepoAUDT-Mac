#!/bin/bash
set -euo pipefail

echo "=========================================="
echo "  RepoCHK Mac 自動アップデート & ビルド"
echo "=========================================="

# 1. フォルダ名のリネーム（RepoChex があれば RepoCHK-Mac に統一）
if [ -d "$HOME/Git/RepoChex" ] && [ ! -d "$HOME/Git/RepoCHK-Mac" ]; then
  echo "📁 フォルダ名を RepoCHK-Mac に変更しています..."
  mv "$HOME/Git/RepoChex" "$HOME/Git/RepoCHK-Mac"
fi

# 2. 作業ディレクトリの特定
TARGET_DIR="$HOME/Git/RepoCHK-Mac"
if [ ! -d "$TARGET_DIR" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  TARGET_DIR="$SCRIPT_DIR"
fi

cd "$TARGET_DIR"

# 3. 最新の修正を取得
echo "📥 最新のコードを取得しています (git pull)..."
git pull origin main

# 4. アプリのビルド & /Applications へのインストール（リポジトリ直下の重複は自動削除）
echo "🔨 RepoCHK Mac をビルドしています..."
./build.sh --install

echo ""
echo "=========================================="
echo "  ✅ アップデートが完了しました！"
echo "  /Applications/RepoCHK Mac.app が最新版です"
echo "=========================================="
sleep 2
