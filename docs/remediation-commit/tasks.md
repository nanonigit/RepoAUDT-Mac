# Verification

1. Verify the original finding and compare a distinct descendant commit using its Git objects.
2. Show the result and commit links in the original finding.
3. Exercise changed and unchanged descendants, invalid and unrelated commits and a missing file.
4. Rebuild and verify the repair already pushed to the self-managed remote, then update the two READMEs.

## Verification / 検証

GitHub's `main` ref resolved to `4fd734693060c0146bb036d117a923d2ce647ee4` before this change. In the signed installed app, the saved finding from `ea780b6` was opened and that full SHA was entered. The app displayed both revisions and reported that the same static rule did not detect that finding at the new commit. The check used local Git objects. All 255 tests passed.

変更前のGitHub `main` が `4fd7346` を指すことを確認した。インストール済みアプリで `ea780b6` の指摘を開き、修正コミットの完全なSHAを入力した。両コミットと「同じ静的ルールではこの指摘を検出しません」が表示された。再監査にはローカルのGitオブジェクトを使用した。テスト255件が通過した。
