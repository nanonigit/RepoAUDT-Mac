# Verification

1. Compare installed app and terminal calls against the same repository.
2. Verify safe classification and process launch options.
3. Verify the installed app endpoint against the recorded audit.

The read from Terminal succeeded. The app-launched CLI failed during TCP connection setup and intermittently timed out. App-launched system HTTPS and the unauthenticated API health probe also failed. The experimental HTTPS retry was discarded. The delivered behavior retains authenticated GitHub CLI reads, distinguishes transport failures from HTTP errors, and preserves saved evidence while no fresh source is available.

In the installed build, the credential check returned present and the GitHub API health check returned offline. The comparison endpoint returned the saved full commit and recorded line with an explicit timed-out live read. Four targeted regression tests and the full suite passed.

インストール済みアプリではローカル資格情報あり、GitHub API は疎通不可と確認した。照合APIは保存コミットと監査時の行を返し、ライブ取得はタイムアウトとして区別した。認証情報を更新せず、PRは作成していない。
