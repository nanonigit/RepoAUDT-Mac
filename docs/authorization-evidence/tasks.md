# Verification plan

1. Capture a positive and a guarded negative fixture. Treat analysis as static.
2. Match the trusted Python handler shape, record pinned provenance and prepare the defensive diff.
3. Validate patch syntax, rule non-recurrence, Git applicability, and the actual self-managed GitHub revision.
4. Verify the result in the installed app and update both README files.

## Verification / 検証

The installed analyzer read the self-managed GitHub revision `ea780b6ddd1896aa07acfc56edfa1aebe4910090` and produced one finding. Its proposed defensive diff passed `git apply --check` and was applied only to a disposable checkout. Repeating the same static rule on that patched file produced no match. The native finding screen displayed the pinned revision, ordered evidence and unified diff. No request was sent to the privileged endpoint. No PR was created. The separate live GitHub source lookup in the native app returned an access error during the screen check.

自己管理のGitHubコミット `ea780b6` で認可の指摘1件を検出した。修正差分は `git apply --check` を通過し、隔離コピーへの適用後は同じ静的ルールで指摘されなかった。実アプリで固定コミット、経路の根拠、修正差分の表示を確認した。対象APIは実行せず、PRも作成しなかった。画面確認時の別経路によるGitHub最新ソース取得はアクセスエラーだった。
