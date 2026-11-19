# Terraform Secrets Manager false positive

A saved audit reported three Terraform assignments as hardcoded passwords. We retrieved the pinned audit revision and the default branch through authenticated GitHub reads. Both resolved to the same commit, and the file's last change preceded it. The old detector reproduced all three alerts against the pinned file.

The generic password rule matched the first quoted fragment of an interpolated ARN and treated it as a literal. The diagnosis followed this chain: a critical alert came from the generic password rule, the rule recognized credential-like keys, its quoted-value heuristic stopped at the interpolation's inner quote, it lacked Terraform reference handling, and regression coverage had no ARN example. Evidence separated the possible causes across source history (same revision and file), detector logic (reproduced), and presentation (saved findings had no versioned source comparison). The diff suggestion consequently proposed a language-inappropriate replacement.

The rule now exempts only a complete Terraform Secrets Manager ARN reference with an optional selector. Literal password detection remains active. The actual file no longer produces these three alerts. Synthetic tests cover the same shape, literal credentials, lookalikes and ambiguous line matches. The UI displays independent repository, branch and file dates, plus both source versions on demand. A verified legacy false positive is labeled without changing the saved audit.

# Terraform Secrets Manager の誤検知

保存済みの監査で Terraform の3つの代入が平文パスワードとして報告された。認証済みの GitHub API で監査時と既定ブランチのコミットを照合したところ一致し、ファイルの最終変更はそのコミットより前だった。監査時のファイルを旧検出器にかけると3件すべてが再現した。

重大判定を出したのは汎用のパスワード検出ルールだった。認証情報風のキー名に反応し、値を囲む引用符から補間式中の最初の引用符までを切り出し、Terraform の参照を扱えず、ARN 参照の回帰例もなかった。履歴（同一コミット・ファイル）、検出（再現済み）、表示（保存済み結果にバージョン付きソース比較がない）に分けて検証した。誤検知に伴い、Terraform に適さない修正案も提示されていた。

完全な Terraform の Secrets Manager ARN 参照だけを汎用ルールの対象から外し、平文の検出は維持した。実ファイルで該当3件が検出されなくなったことを確認した。回帰テストには類似した参照、平文、紛らわしい式、対応行を特定できない例を含めた。画面では更新日時と両時点のソースを個別に示し、保存済み監査を保持したまま、確認済みの誤検知を表示する。
