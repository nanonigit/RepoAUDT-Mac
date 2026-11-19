# Implementation and verification

1. Separate URL parsing, GitHub resolution and exact checkout.
2. Route the analyzer and exported reports through the pinned source.
3. Test default branch, explicit ref, checkout mismatches and local dirty-copy isolation.
4. Verify the packaged scanner with an authenticated read from a self-managed repository.

## Verification / 検証

A GitHub read of the self-managed repository resolved commit `ba2c71a92a4fb75cf28c78af9e27849399f3205b` and tree `5152830e8073c14e8bac37dba5913f42f82d55dd`. The explicit commit URL produced those same IDs in the analysis. A local fixture confirmed that a dirty working tree was preserved, repository attributes could not transform source bytes, symlinks did not point outside the checkout, and a tree mismatch stopped acquisition before analysis.

自己管理リポジトリの指定コミットをGitHubから取得し、監査結果のコミットとツリーが一致することを確認した。合成リポジトリでは、元の未コミット編集が保持されること、属性によるソース変換を防ぐこと、リンク先をたどらないこと、ツリー不一致時は監査を開始しないことを確認した。
