# Implementation and verification

1. Trace the static finding from the HTTP handler to the execution capability, and identify the built-in callers.
2. Retire the route and convert its callers to the existing copy workflow.
3. Validate the absence of the capability with static analysis, and check the generated HTML and bilingual labels.
4. Build the bundle and record the verified behavior.

## Verification / 検証

The original finding reached the command runner through an HTTP handler shared by the inspector input and suggested-fix buttons. The repaired handler returned HTTP 410 to an empty request in the signed installed app. The same static rule reported no match for the repaired server. The original finding and its pinned diff remained available, and the installed audit view showed the command-copy control and the before/after result for the saved diff. All 252 tests passed.

旧インスペクターの入力欄と修正ボタンは共通のHTTPハンドラーを経由していた。署名済みのインストール版で廃止APIが空のリクエストにHTTP 410を返し、修正後のサーバーは同じ静的ルールで指摘されなかった。監査記録と固定コミットの修正差分も残り、コピーボタンと保存差分の適用前後を実アプリで確認した。テスト252件が通過した。
