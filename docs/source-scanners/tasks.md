# Implementation

1. Confirm installed tool option and report formats.
2. Stage tracked files, run both tools, validate outputs, and merge results.
3. Verify synthetic diagnostics, redaction, tracked-file boundaries and fallbacks.
4. Build the app, verify the audit report and update both READMEs.

## Verification / 検証

Ruff 0.17.5 and Gitleaks 8.30.1 detected the intended synthetic issues. Ruff emitted canonical macOS paths, so the staging root is resolved before report paths are checked. Tests make sure ignored or untracked files are outside the scope, a Terraform ARN reference is not reported as a credential, and preview/report output hides credential values. The app records failures and partial coverage by tool.

Ruff 0.17.5 と Gitleaks 8.30.1 で合成データの指摘を確認した。macOSでRuffが返した正規化済みパスに合わせ、作業用ルートを正規化してから検証する。非追跡ファイルを対象外とし、TerraformのARN参照を誤検知しないこと、監査レポートと比較プレビューに秘密値が出ないことを回帰テストで確認した。ツールごとに失敗と部分実行を記録する。
