# Implementation

1. Confirm the official CLI flags and reproduce findings on a synthetic workflow.
2. Stage bounded workflow files and validate SARIF before merging findings.
3. Verify normal, clean, missing-tool and malformed-workflow paths and symlink handling.
4. Build the app and update both README files.

## Verification / 検証

A synthetic workflow reproduced unpinned actions and persisted checkout credentials with zizmor 1.32.0. The same fixture also showed why both engines are retained: only the built-in rule reported the explicit broad permission in that run. Tests cover an empty report, invalid YAML, missing scanner, symlinks, duplicate findings, and unexpected source paths. SARIF snippets and arbitrary messages are discarded before saving findings.

合成ワークフローで、zizmor 1.32.0 が未固定Actionとチェックアウト認証情報の保持を検出した。同じ入力の明示的な過剰権限は内蔵ルールのみが報告したため、両方の結果を統合した。指摘なし、不正なYAML、スキャナー未導入、シンボリックリンク、重複指摘、対象外パスを検証した。SARIFのソース抜粋と任意のメッセージは保存しない。
