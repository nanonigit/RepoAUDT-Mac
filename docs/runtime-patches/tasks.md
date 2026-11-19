# Runtime patch checks

1. Verify the current shape of the official feeds.
2. Add the repository evidence and version comparisons.
3. Integrate the results and suppress misleading generic installation snippets.
4. Verify fixtures and current live vendor responses, then rebuild and update both READMEs.

## Verification / 検証

Tests distinguish version pins, ranges, aliases, digests and unknown images. They cover the nginx fixed-branch exception, future Node.js releases, a PHP named-symbol candidate, feed failures, and Go and PostgreSQL release branches. The live Go feed exposed whitespace inside the phrase “security fixes”. Its parser and fixture now normalize that whitespace.

固定版・範囲指定・ステージ別名・ダイジェスト・未対応イメージを区別できることを確認した。nginxの修正済み系列、Node.jsの将来リリース、PHPの関数名候補、取得失敗、GoとPostgreSQLの系列を検証した。Goの公式HTMLで「security」と「fixes」の間に改行があるケースを確認し、空白の正規化と回帰例を追加した。
