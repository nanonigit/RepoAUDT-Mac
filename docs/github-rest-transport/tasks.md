# Tasks

1. Confirm local credential retrieval and live connectivity with the two HTTP clients.
2. Add a bounded opt-in transport and regression tests for scope and redaction.
3. Test the repository, branch and source reads with an existing authorized repository.
4. Update the English and Japanese README and verify the macOS bundle.

## Verification / 検証

The opt-in transport resolved the self-managed repository's default branch and compared the saved Terraform finding to the live GitHub file from the terminal backend. The signed app selected REST as requested, but its live read timed out under the local desktop launch environment. No network rule changes were made. All 259 tests passed.

ターミナルから起動したバックエンドで、自己管理リポジトリの既定ブランチの確定と、保存済みTerraform指摘の現行コードとの照合に成功した。署名済みの実アプリではRESTモードが選択されたが、デスクトップからの起動では照会がタイムアウトした。ネットワークルールは変更していない。テスト259件が通過した。
