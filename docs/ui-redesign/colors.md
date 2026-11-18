# 色の役割と検証

RepoAUDT Mac は NetworkPNTR Mac / NetworkISPR Mac と同じ macOS の意味に沿って色を使う。色のみで状態を伝えず、アイコンと日英ラベルを添える。

| 役割 | 使用箇所 | 根拠 |
| --- | --- | --- |
| 青・操作 | 主操作、リンク、選択、キーボードフォーカス | 押せる場所と現在の選択を示す |
| 赤・危険 | Critical / High、接続失敗 | 重大な対処事項と失敗を示す |
| 橙・警告 | Medium / Warning | 注意が必要な状態を示す |
| 青・情報 | Low / Info、改善候補のラベル | 情報ラベルにアイコンと重要度を併記する |
| 緑・確認済み成功 | 接続テスト成功、保存完了 | 操作の成功が確認された場合に限る |
| グレー・未確認と通常情報 | 0件、未確認、通常の構成要素、補足文 | 指摘ゼロから安全を断定しない |

`Resources/webui/semantic-colors.json` がライト・ダーク共通の配色定義。SwiftUI の `SemanticColors` と生成 HTML の CSS 変数で共有する。各コンポーネントでは具体的なHEX値を指定せず、役割を参照する。

主操作の背景と文字色、本文・補足・操作ラベルと3種類の背景、4種類の状態ラベルと各背景、選択状態の合計46組を検証する。すべて4.5対1以上を条件とする。これは定義済みトークンの検証であり、全画面のアクセシビリティ適合宣言ではない。

## 調査と採用

- [Apple HIG Color](https://developer.apple.com/design/human-interface-guidelines/color) の、一貫した意味、システムの外観への追従、色以外の手がかりという原則を採用する。
- [meodai color-expert](https://github.com/meodai/skill.color-expert) を skills CLI で検索し、Lazyweb 経由で SKILL.md を取得。参照値・意味・コンポーネントの3層と、両テーマでのコントラスト検証を採用する。
- [RNVizion rnv-color-mcp](https://github.com/RNVizion/rnv-color-mcp) はWCAGコントラストと色変換のMCP候補としてREADMEを確認。今回の定義はローカルで数値検証する。
- [claude-ui-color-palette](https://github.com/a-ng-d/claude-ui-color-palette) はパレット生成・監査の候補としてREADMEを確認。

検証コマンド `python3 -m unittest discover -s tests/ui -v`。
