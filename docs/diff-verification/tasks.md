# Verification

1. Validate local object acquisition and the recorded authorization finding.
2. Verify the proposed diff in a scratch copy and expose the before/after result.
3. Test rejected diffs, changed local files and absent or wrong revisions.
4. Verify the installed app with a saved self-managed GitHub finding.

## Verified on 2026-11-20

The installed macOS app opened the saved `nanonigit/RepoAUDT-Mac` audit at
`ea780b6ddd1896aa07acfc56edfa1aebe4910090`. In the finding for
`Resources/backend/server.py:555`, **Verify diff locally** reported
detected before and undetected by the same static rule after, using the
local Git object. The candidate disables the flagged route in the disposable copy.
All 249 existing and new tests passed.

インストール済みアプリで、固定コミット `ea780b6ddd1896aa07acfc56edfa1aebe4910090`
の認可の指摘を開きました。「修正差分をローカル検証」を実行し、ローカルのGitオブジェクトから
取得したコードで、適用前は検出、隔離コピーで対象ルートを無効化した後は同じ静的ルールで
未検出となることを確認しました。既存・追加テスト計249件が通過しました。
