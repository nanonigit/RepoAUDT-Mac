# UI 設計

NetworkPNTR Mac と NetworkISPR Mac の実画面を確認。SwiftUI NavigationSplitView、List、標準ツールバー、本文先頭の短い見出し、余白と区切りによる階層を共有する。

Lazyweb の desktop 検索 `developer security dashboard sidebar issues repository` を実施。Cycode のリポジトリ解析入口、GitHub の検索可能なリポジトリ一覧を参照。検索資料はWeb製品が中心。兄弟アプリのネイティブ画面を操作体系の基準にする。

- SwiftUI のシェルが画面選択、保存済みリポジトリ、検索、言語を管理する。
- WKWebView の既存解析・監査処理は固定コマンドとJSON値で呼び出す。ページから渡す情報は表示用のリポジトリ要約に限定する。
- 埋め込み時は二重のサイドバーとツールバーを取り除き、監査本文と図、必要時の詳細を表示する。
- グレーの背景、システムフォント、青の主操作、控えめな境界線を共通言語にする。警告は個別の意味に限定する。
- ダッシュボードでは保存済みの件数とコミットを表示する。ゼロ件から安全性を断定しない。

参考 https://www.lazyweb.com/agentic-search/31e07828-3f08-402a-bb88-04dcc605969e
