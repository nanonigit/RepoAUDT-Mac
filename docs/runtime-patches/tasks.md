# Runtime patch checks

1. Verify the current shape of the official feeds.
2. Add the repository evidence and version comparisons.
3. Integrate the results and suppress misleading generic installation snippets.
4. Verify fixtures and current live vendor responses, then rebuild and update both READMEs.

## Verification / 検証

Tests distinguish version pins, ranges, aliases, digests and unknown images. They cover the nginx fixed-branch exception, future Node.js releases, a PHP named-symbol candidate, feed failures, and Go and PostgreSQL release branches. The live Go feed exposed whitespace inside the phrase “security fixes”. Its parser and fixture now normalize that whitespace.

固定版・範囲指定・ステージ別名・ダイジェスト・未対応イメージを区別できることを確認した。nginxの修正済み系列、Node.jsの将来リリース、PHPの関数名候補、取得失敗、GoとPostgreSQLの系列を検証した。Goの公式HTMLで「security」と「fixes」の間に改行があるケースを確認し、空白の正規化と回帰例を追加した。

1. Reproduce the missed runtime lookup using an official image tag that references a global build argument.
2. Capture bounded version defaults and map supported `FROM` references to official products.
3. Verify escaped syntax, stage-local shadowing, missing values, digests and end-to-end advisory lookup.
4. Update the English and Japanese READMEs and run the existing suites.

The missed lookup reproduced with nginx: a variable tag was listed as an unmapped image and the advisory feed was never consulted for its default. The inventory now retains the original image expression and Dockerfile line locations. A live run against the vendor feed matched advisories for an older nginx default. Regression fixtures cover the default, stage-local shadowing, an escaped or unresolved expression, a pinned digest, and the official-advisory result.

nginxのタグを変数で指定すると未対応イメージになり、公式情報と照合されないことを再現した。元の式と行番号を保持したうえで、公式フィードを使い、古いnginxの既定版に該当する情報を取得できた。既定値、ステージ内の再宣言、未解決・エスケープされた式、ダイジェスト指定、アドバイザリ結果を回帰テストで確認した。
