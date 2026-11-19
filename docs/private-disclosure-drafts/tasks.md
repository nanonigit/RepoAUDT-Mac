# Verification

1. Validate the repository, full audit SHA and line number before composing the draft.
2. Show both language variants in the existing finding detail with an explicit copy control.
3. Confirm the draft omits source, patch and free-form saved finding text and that unsupported records cannot initialize it.
4. Build, verify in the installed app, and update both READMEs.

## Verification / 検証

The signed installed app displayed the editable Japanese draft, explicit copy control and security-policy link for the saved GitHub-pinned authorization finding. Three JavaScript tests exercised both languages, rejection of unsupported evidence, exclusion of raw saved text and copying the edited value. All 262 tests passed.

署名済みのインストール版で、固定コミットの認可指摘から日本語の編集欄、コピーボタン、セキュリティポリシーのリンクを確認した。JavaScriptの3テストで日英表示、対象外データの拒否、保存済みの生テキストを含めないこと、編集後の値のコピーを検証した。テスト262件が通過した。
