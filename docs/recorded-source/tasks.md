# Recorded source verification

1. Compare CLI and native backend reads.
2. Add recorded excerpts and a partial comparison state.
3. Test pinned identity, redaction and offline fallback.
4. Verify a re-recorded self-managed finding in the installed app.

## Verification / 検証

The installed analyzer re-read the original GitHub revision and stored four traced lines. The macOS finding showed the saved excerpts with pinned links, and the installed evidence endpoint returned HTTP 200 with the audited line and an explicit unavailable current state. GitHub CLI reads worked independently, but the app's live comparison remained unavailable. Regression tests cover identity mismatches and exclusion of recorded source text from AI context.

実際の固定コミットから4ステップの抜粋を再取得し、実アプリでコミット付き行リンクと抜粋の表示を確認した。インストール済みの証拠APIは、最新ソース取得が不成立でも HTTP 200 で監査時の行と最新未取得の状態を返した。CLI単体では取得できたが、アプリのライブ照合は未復旧。コミット不一致と、AIへの抜粋非送信を回帰テストで確認した。
