# RepoAUDT Mac

[English](README.md) | **日本語**

RepoAUDT Mac は、GitHub リポジトリのコードを解析し、構成図とともにセキュリティ・コード品質の指摘を確認できるネイティブ macOS アプリです。**AUDT** は **Audit（監査）** の略です。

GitHub リポジトリの URL または `owner/repo` を入力し、解析結果を構成図・シーケンス図と照らし合わせて確認できます。非公開リポジトリにはローカルの GitHub / Git 認証によるアクセス権が必要です。指摘や修正案はレビューが必要であり、指摘ゼロから安全性を断定することはできません。

## 主な機能

- **リポジトリの作業画面：** セクションの並び替え・折りたたみに対応したダッシュボード、検索、構成図・実行フロー・監査・チャット共通のサイドバー選択ハイライト、および **リスクスコアが高い順** などの並び替え。
- **コード監査：** P0〜P3 の優先度分類とティア別ユニーク ID（`P0-01`, `P1-01`, `P2-01` …／各ティア内は CISA KEV → 確信度 → Severity → EPSS 降順で自動整列）、静的解析、依存パッケージの脆弱性チェック、Web・サプライチェーン設定検査（`dangerouslyAllowSVG`、CORS ワイルドカード + credentials、不審な npm ライフサイクルスクリプト、秘密鍵ストアやソースマップのコミット）、根拠、対象コンポーネント、修正案を表示。英語優先・日本語併記の依頼文コピーとレポート保存に対応。
- **ライブ脅威インテリジェンス照合：** **CISA KEV**（悪用確認済み脆弱性）および **GitHub Security Advisories (Critical)** の公式フィードを取得し、保存済みリポジトリの技術スタック・設定ファイル（`Dockerfile`, `nginx.conf`, `composer.json`, `package.json`, `*.tf`, Kubernetes Ingress）や検出済み CVE と自動照合してダッシュボードに表示します。「全リポジトリを解析」完了時にも自動で再取得・照合し、一括監査レポートのコピーにも結果を含めます。
- **修正依頼トラッカー：** 指摘ごとの Slack / GitHub Issue 依頼状況と経過日数を記録し、`すべて` / `未依頼` / `依頼済み` フィルタ、再スキャン時の自動解消、`gh issue create` による GitHub Issue 作成に対応。
- **利用コンポーネントとセキュリティ更新：** リポジトリに宣言されたイメージ・ランタイム版・互換要件を一覧化します。PHP・nginx・Node.js・Go・PostgreSQLの公式情報と照合し、確認できた修正版やセキュリティリリースの出典を表示します。
- **マルチスキャナー連携：** **Gitleaks**（最新ツリー＋Git 履歴）、**TruffleHog**（オフライン `--no-verification`）、**Trivy**（SCA・IaC）、**Semgrep**、**Hadolint**（Dockerfile）、**Ruff**、**zizmor** を統合。秘密情報の候補はソース比較とレポートで伏せ、各 CLI の導入状態は「実行環境・更新」で確認できます。
- **認可の根拠：** コミットを固定したGitHub監査で、対応するPython HTTPハンドラーの入口、認可境界、入力、高権限処理の位置をたどります。指摘には伏字処理した監査時の抜粋、固定コミットへのリンク、静的に確認した修正差分が付きます。GitHubの最新ソースを取得できないときも保存済みの根拠を表示します。
- **現行ソースと更新履歴：** 指摘を開くと、監査時と現在の行、コミットへのリンク、既定ブランチの最新コミット、リポジトリの最終 Push、ファイルの最終変更を確認できます。最新情報の取得には認証済みの GitHub CLI を使用します。
- **監査チャット：** サイドバーまたは指摘から開始できます。質問ごとに GitHub を再確認し、質問・直近のメッセージ・比較のメタデータを設定済み AI に送信します。ソース行は作業画面に留めます。
- **ネイティブな操作：** NetworkPNTR Mac / NetworkISPR Mac に合わせた macOS のサイドバーとツールバー、必要時に開く詳細、日英切替。
- **意味を統一した配色：** ライト／ダークに対応。青は操作・選択、赤は重大な指摘・失敗、黄／橙は注意、緑は確認済みの成功。重要度には文字と記号も併記。
- **クラウド AI：** OpenAI / Claude / Gemini / Groq の設定と接続テスト、既存の AI 監査連携。
- **ローカル LLM：** ループバックの OpenAI 互換 API に、接続先 URL とモデル名を指定して接続。API キーは任意。
- **MCP サーバー：** リポジトリ一覧、構成、監査レポート、リポジトリ解析、コード断片の監査、CycloneDX SBOM 出力、SARIF 出力の7ツールを stdio / ローカル HTTP で提供。
- **MCP クライアント：** stdio / HTTP サーバーへの接続、ツールの定義確認、JSON 引数の入力、明示操作によるツール実行。

## 必要な環境

- macOS 14 以降の Apple Silicon Mac。現在のビルドスクリプトは `arm64` を対象としています。
- `swiftc` を含む Xcode Command Line Tools。
- `/opt/homebrew/bin/python3`、`/usr/local/bin/python3`、`/usr/bin/python3` のいずれかにある Python 3。
- Git、および解析対象にアクセスできる GitHub 認証。解析ではローカルの `gh` / Git 認証を利用できます。
- GitHub、脆弱性照会、クラウド AI の利用時はインターネット接続。ローカル推論には別途起動した互換モデルサーバーが必要です。

## ビルドとインストール

```bash
./build.sh --install
```

`/Applications/RepoAUDT Mac.app` にインストールされます。

インストールせず、リポジトリ内にアプリを生成する場合：

```bash
./build.sh --no-install
```

## 任意のローカルスキャナー

```bash
brew install zizmor ruff gitleaks trufflehog trivy semgrep hadolint
```

「再スキャン」で導入済み CLI スキャナーの結果を保存済みの監査に統合できます。7 ツールすべての導入状態は「実行環境・更新」で確認できます。zizmor はローカルのワークフローファイル最大 25 件をオフライン解析し、GitHub トークンは渡しません。いずれかの CLI が未導入・タイムアウト・解析エラーの場合も内蔵チェックは継続して動作し、実行状態は監査結果および MCP レポートに記録されます。

Gitleaks は追跡対象ファイルのスナップショットに加えて Git コミット履歴も走査し、TruffleHog はオフラインモード（`--no-verification`）で HEAD 検出結果と重複排除しながら解析します。Hadolint は `Dockerfile`、Trivy は SCA・IaC、Semgrep と Ruff はソースコードを解析します。

## 使い始める

1. RepoAUDT Mac を起動し、「リポジトリを追加」を選びます。
2. GitHub URL または `owner/repo` を入力し、解析を開始します。
3. リポジトリを選び、サイドバーから監査結果・構成図・実行フローを開きます。必要に応じて詳細を表示します。
4. AI 解析を使う場合は「AI 接続」でプロバイダーを設定します。ローカル推論では、接続先 URL とサーバーが公開している正確なモデル名を指定し、保存・接続テストを行います。
5. 「MCP」から本アプリのサーバー設定をコピーするか、クライアントとして外部サーバーを設定します。実行前にツールの引数を確認してください。

保存済み解析は記録されたコミット時点の結果です。新しいコードを確認する際は再度解析してください。

## ランタイムのパッチ確認範囲

再スキャン後に「使用コンポーネントとセキュリティ更新の調査」を開きます。DockerfileとYAMLのイメージ、バージョンファイル、ツールチェーン設定、対応する互換要件を一覧にします。公式フィード未対応、版未確定、取得失敗はそれぞれ区別します。宣言ファイル最大200件、一覧最大300項目、製品ごとに最大16の版が対象です。監査画面は版ごとに先頭15件を表示し、MCP監査レポートは照合済みの版ごとの結果を保持します。

PHPはphp-srcの公開アドバイザリ直近50件とサポート終了情報、nginxとPostgreSQLはそれぞれの公式アドバイザリを参照します。Node.jsとGoは同系列のセキュリティリリースを案内します。PHPのアドバイザリが関数名を公開している場合、PHPファイル最大120件から名前が一致する行を探します。稼働版や実行経路、ディストリビューションのバックポート、イメージの中身、動的に解決される版には別途根拠が必要です。

公式Dockerイメージでは、最初の `FROM` より前に宣言された単純な数値形式の `ARG` 既定値を解決できます。引数の宣言行とイメージの指定行を記録し、既定版を公式情報と照合します。ビルド時に引数を上書きすると、使われる版が変わることがあります。解決できない式やダイジェスト固定のイメージは従来どおり版未確定とします。

## 監査対象のコミット

GitHubリポジトリのURLから既定ブランチのコミットを確定します。`/tree/<ブランチ名>` や `/commit/<完全なSHA>` も指定できます。ブランチ名のスラッシュは `%2F` に置き換えてください。検証済みのコミットとツリーを隔離された一時ディレクトリに取得して監査し、対象の情報はMCP監査レポートにも記録します。ローカルパスを明示した監査は、ローカル作業ツリーの解析として記録します。 バックグラウンド更新の対象は個別リポジトリの既定ブランチです。明示指定したコミット・ブランチの監査結果は保持します。ブランチ指定の監査は、同じブランチの最新コミットと照合します。GitHubの診断はローカルの資格情報とAPI疎通を分けて報告します。 対応する認可指摘の「修正差分をローカル検証」で、隔離コピーに差分を適用し、同じ静的ルールの適用前後を比較できます。

対応する認可指摘では、監査コミットの後続コミットの完全なSHAを入力し、「修正コミットを再監査」を選ぶと、同じファイルを元のルールで再確認できます。対応するローカルのチェックアウトに両コミットが必要です。結果には両方のコミットとローカルGitによる確認結果を表示します。

GitHubの資格情報が見つかり、RepoAUDT Mac内でだけAPI疎通に失敗する場合は、アプリとそのアプリが起動するGitHub CLI（`gh`）の送信ルールを確認してください。ターミナルの `gh` が使えても、アプリ個別のルールが `github.com` への接続を遮断することがあります。対応する指摘では監査時の根拠を表示し、GitHubからの取得が成功するまでは現行ソースを取得できないことを示します。

GitHub CLIでローカル資格情報を取得できてもHTTP通信に失敗する場合は、RepoAUDT Macを終了し、`open --env REPOAUDT_GITHUB_TRANSPORT=rest -a "/Applications/RepoAUDT Mac.app"` で起動できます。この起動中は同じ資格情報でGitHubの読み取り専用REST APIを使い、監査時はGitチェックアウトを別途検証します。

コマンド案がある指摘では「コマンドをコピー」を選び、ご自身のターミナルで内容を確認できます。旧内蔵シェルのAPIはHTTP 410を返します。

## 検証と現在の実装範囲

コミットが固定された対応する認可指摘では、「非公開報告の下書き」を開いて内容の確認・編集・コピーができます。「セキュリティポリシー」のリンクから、メンテナーが指定する非公開の報告先を確認できます。下書きは現在の画面内に保持されます。

```bash
node --test tests/ui/test_disclosure_draft.js
python3 tests/e2e/run_all_tests.py
python3 -m unittest discover -s tests/connections -v
python3 -m unittest discover -s tests/ui -v
python3 -m unittest discover -s tests/audit -v
python3 -m unittest discover -s tests/audit-tools -v
python3 -m unittest discover -s tests/source-scanners -v
python3 -m unittest discover -s tests/runtime-patches -v
python3 -m unittest discover -s tests/source-revision -v
python3 -m unittest discover -s tests/authorization -v
python3 -m unittest discover -s tests/recorded-source -v
python3 -m unittest discover -s tests/github-transport -v
python3 -m unittest discover -s tests/diff-verification -v
```

既存テスト197件、接続テスト8件、配色テスト3件、監査証拠テスト5件、ワークフロー監査テスト4件、ソーススキャナーテスト5件、ランタイムパッチテスト6件、監査対象コミットのテスト5件、認可根拠テスト5件、保存ソーステスト3件、GitHub接続テスト4件、差分検証テスト4件が成功しました。配色テストはライト／ダーク合計46組の文字・背景色を対象とし、すべてコントラスト4.5:1以上です。これは配色定義の検証であり、全画面のアクセシビリティ適合を保証するものではありません。

ローカル LLM はモック HTTP サーバーへのリクエストで検証済みですが、Ollama / LM Studio の実モデルは未検証です。インストール済みアプリで MCP のツール取得とコード断片の監査も確認しています。PR 送信・進捗追跡・修正の解消確認までの一連の運用は、今回の完成範囲に含みません。

## 設計・実装資料

以下の実装資料は日本語で記載しています。

- [UI 要件](docs/ui-redesign/requirements.md)
- [UI 設計](docs/ui-redesign/design.md)
- [配色の役割・参考資料・コントラスト検証](docs/ui-redesign/colors.md)
- [検証記録](docs/ui-redesign/verification.md)
- [修正差分のローカル検証](docs/diff-verification/design.md)
- [保存ソースの設計](docs/recorded-source/design.md)
- [認可の根拠と修正差分の設計](docs/authorization-evidence/design.md)
- [コミット固定の設計](docs/commit-pinned-audit/design.md)
- [ランタイムパッチの設計](docs/runtime-patches/design.md)
- [ソーススキャナーの選定と対象範囲](docs/source-scanners/design.md)
- [監査ツールの比較と設計](docs/audit-tools/design.md)
- [監査証拠の設計](docs/audit-evidence/design.md)と[誤検知の調査記録](docs/audit-evidence/incident.md)

機能・セットアップ手順・検証範囲を変更する際は、この日本語 README と[英語版 README](README.md) を同時に更新してください。
