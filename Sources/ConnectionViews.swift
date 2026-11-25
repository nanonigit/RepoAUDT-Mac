import AppKit
import Foundation
import SwiftUI

@MainActor
final class ConnectionStore: ObservableObject {
    @Published var provider = "openai"
    @Published var model = ""
    @Published var key = ""
    @Published var keyStatus = ""
    @Published var localURL = "http://127.0.0.1:11434/v1"
    @Published var transport = "stdio"
    @Published var command = "/usr/bin/python3"
    @Published var arguments = "[]"
    @Published var endpoint = "http://127.0.0.1:18765/api/mcp"
    @Published var tokenEnvironment = ""
    @Published var tools: [MCPTool] = []
    @Published var toolName = ""
    @Published var toolArguments = "{}"
    @Published var serverConfig = ""
    @Published var feedback = ""
    @Published var output = ""
    @Published var busy = false
    @Published var failed = false
    @Published var copilotInstalled = false
    @Published var copilotVersion = ""
    @Published var copilotPythonPath = ""
    @Published var copilotStatusLoaded = false
    @Published var geminiCliInstalled = false
    @Published var geminiCliVersion = ""
    @Published var geminiCliPath = ""
    @Published var geminiCliAuthenticated = false
    @Published var geminiCliAuthMethod = ""
    private var settings: [String: Any] = [:]
    var port = 18765

    struct MCPTool: Identifiable {
        let name: String
        let description: String
        let schema: String
        var id: String { name }
    }

    func request(_ path: String, body: [String: Any]? = nil) async throws -> [String: Any] {
        guard let url = URL(string: "http://127.0.0.1:\(port)\(path)") else { throw URLError(.badURL) }
        var request = URLRequest(url: url)
        request.timeoutInterval = 150
        if let body {
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NSError(domain: "RepoAUDT", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid response from local engine"])
        }
        if (response as? HTTPURLResponse)?.statusCode != 200 || json["ok"] as? Bool == false {
            throw NSError(domain: "RepoAUDT", code: 2, userInfo: [NSLocalizedDescriptionKey: json["error"] as? String ?? "Connection request failed"])
        }
        return json
    }

    func run(_ work: @escaping () async throws -> Void) {
        guard !busy else { return }
        busy = true
        feedback = ""
        failed = false
        Task {
            defer { busy = false }
            do { try await work() }
            catch { failed = true; feedback = error.localizedDescription }
        }
    }

    func selectProvider() {
        let models = settings["models"] as? [String: String] ?? [:]
        model = models[provider] ?? ""
        let configured = settings["configured"] as? [String: Bool] ?? [:]
        keyStatus = configured[provider] == true ? ((settings["keys_masked"] as? [String: String])?[provider] ?? "") : ""
        key = ""
        feedback = ""
    }

    func loadAI() {
        run {
            self.settings = try await self.request("/api/settings")
            let active = self.settings["active_provider"] as? String ?? "auto"
            self.provider = active == "auto" ? "openai" : active
            self.localURL = self.settings["local_base_url"] as? String ?? self.localURL
            self.selectProvider()
            await self.refreshCopilotStatus()
            await self.refreshGeminiCliStatus()
        }
    }

    func refreshGeminiCliStatus() async {
        do {
            let status = try await self.request("/api/connections/gemini-cli/status")
            self.geminiCliInstalled = status["installed"] as? Bool ?? false
            self.geminiCliVersion = status["version"] as? String ?? ""
            self.geminiCliPath = status["path"] as? String ?? ""
            self.geminiCliAuthenticated = status["authenticated"] as? Bool ?? false
            self.geminiCliAuthMethod = status["auth_method"] as? String ?? ""
        } catch {}
    }

    func installOrUpdateGeminiCli(english: Bool) {
        run {
            let result = try await self.request("/api/connections/gemini-cli/install", body: [:])
            self.geminiCliInstalled = result["installed"] as? Bool ?? false
            self.geminiCliVersion = result["version"] as? String ?? ""
            self.geminiCliPath = result["path"] as? String ?? ""
            self.geminiCliAuthenticated = result["authenticated"] as? Bool ?? false
            self.geminiCliAuthMethod = result["auth_method"] as? String ?? ""
            let verLabel = self.geminiCliVersion.isEmpty ? "" : " (v\(self.geminiCliVersion))"
            self.feedback = english
                ? "Gemini CLI\(verLabel) is ready."
                : "Gemini CLI\(verLabel) の準備が完了しました。"
        }
    }

    func refreshCopilotStatus() async {
        do {
            let status = try await self.request("/api/connections/copilot/status")
            self.copilotInstalled = status["sdk_installed"] as? Bool ?? false
            self.copilotVersion = status["sdk_version"] as? String ?? ""
            self.copilotPythonPath = status["python_executable"] as? String ?? ""
            self.copilotStatusLoaded = true
        } catch {
            self.copilotStatusLoaded = false
        }
    }

    func installOrUpdateCopilotSDK(english: Bool) {
        run {
            let result = try await self.request("/api/connections/copilot/install", body: [:])
            self.copilotInstalled = result["sdk_installed"] as? Bool ?? false
            self.copilotVersion = result["sdk_version"] as? String ?? ""
            self.copilotPythonPath = result["python_executable"] as? String ?? ""
            self.copilotStatusLoaded = true
            let prev = result["previous_version"] as? String ?? ""
            let updated = result["updated"] as? Bool ?? false
            let verLabel = self.copilotVersion.isEmpty ? "" : " (v\(self.copilotVersion))"
            if prev.isEmpty {
                self.feedback = english
                    ? "Installed GitHub Copilot SDK\(verLabel)."
                    : "GitHub Copilot SDK\(verLabel) をインストールしました。"
            } else if updated {
                self.feedback = english
                    ? "Updated GitHub Copilot SDK from v\(prev) to v\(self.copilotVersion)."
                    : "GitHub Copilot SDK を v\(prev) から v\(self.copilotVersion) にアップデートしました。"
            } else {
                self.feedback = english
                    ? "GitHub Copilot SDK\(verLabel) is up to date."
                    : "GitHub Copilot SDK\(verLabel) は最新の状態です。"
            }
        }
    }

    func saveAI(test: Bool, english: Bool) {
        run {
            let body: [String: Any] = ["active_provider": self.provider,
                                       "models": [self.provider: self.model],
                                       "keys": [self.provider: self.key],
                                       "local_base_url": self.localURL]
            let saved = try await self.request("/api/settings", body: body)
            self.settings = saved["settings"] as? [String: Any] ?? self.settings
            self.selectProvider()
            if test {
                let result = try await self.request("/api/test-llm", body: ["provider": self.provider])
                self.feedback = english ? "Inference test succeeded using \(result["model"] as? String ?? self.model)." :
                    "\(result["model"] as? String ?? self.model) の推論テストが成功しました。"
            } else {
                self.feedback = english ? "Saved. Future AI audits use this provider." : "保存しました。次の AI 監査からこの接続先を使用します。"
            }
        }
    }

    func mcpConfig() throws -> [String: Any] {
        guard let data = arguments.data(using: .utf8),
              let args = try JSONSerialization.jsonObject(with: data) as? [String] else {
            throw NSError(domain: "RepoAUDT", code: 3, userInfo: [NSLocalizedDescriptionKey: "Arguments must be a JSON array of strings"])
        }
        return ["transport": transport, "command": command, "args": args, "url": endpoint, "token_env": tokenEnvironment]
    }

    static func jsonText(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    func loadMCP() {
        run {
            let config = try await self.request("/api/connections/mcp")
            self.transport = config["transport"] as? String ?? "stdio"
            self.command = config["command"] as? String ?? self.command
            self.arguments = try Self.jsonText(config["args"] ?? [])
            self.endpoint = config["url"] as? String ?? self.endpoint
            self.tokenEnvironment = config["token_env"] as? String ?? ""
            let server = try await self.request("/api/mcp")
            self.serverConfig = try Self.jsonText(server["client_config"] ?? [:])
        }
    }

    func saveMCP(english: Bool) {
        run {
            _ = try await self.request("/api/connections/mcp", body: self.mcpConfig())
            self.feedback = english ? "Connection settings saved." : "接続設定を保存しました。"
        }
    }

    func testMCP(english: Bool) {
        tools = []
        output = ""
        run {
            let result = try await self.request("/api/connections/mcp/test", body: ["config": self.mcpConfig()])
            let data = result["data"] as? [String: Any] ?? [:]
            let list = (data["result"] as? [String: Any])?["tools"] as? [[String: Any]] ?? []
            self.tools = try list.map { tool in
                MCPTool(name: tool["name"] as? String ?? "", description: tool["description"] as? String ?? "",
                        schema: try Self.jsonText(tool["inputSchema"] ?? [:]))
            }
            self.toolName = self.tools.first?.name ?? ""
            let name = (data["serverInfo"] as? [String: Any])?["name"] as? String ?? "MCP"
            self.feedback = english ? "Connected to \(name). \(self.tools.count) tools available." :
                "\(name) に接続しました。\(self.tools.count)個のツールが利用できます。"
        }
    }

    func callTool() {
        run {
            guard let data = self.toolArguments.data(using: .utf8),
                  let args = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw NSError(domain: "RepoAUDT", code: 4, userInfo: [NSLocalizedDescriptionKey: "Tool arguments must be a JSON object"])
            }
            let result = try await self.request("/api/connections/mcp/call", body: [
                "config": self.mcpConfig(), "params": ["name": self.toolName, "arguments": args]])
            self.output = try Self.jsonText(result["data"] ?? [:])
        }
    }
}

struct AIConnectionView: View {
    @StateObject private var store = ConnectionStore()
    let english: Bool
    let port: Int

    var body: some View {
        Form {
            Section {
                Text(english ? "Choose the AI used for repository audits." : "リポジトリ監査に使用する AI を選びます。")
                    .foregroundStyle(.secondary)
                Picker(english ? "Provider" : "接続先", selection: $store.provider) {
                    Text("OpenAI").tag("openai")
                    Text("Claude").tag("claude")
                    Text("Gemini (API Key)").tag("gemini")
                    Text("Antigravity CLI (Gemini)").tag("gemini_cli")
                    Text("Groq").tag("groq")
                    Text("GitHub Copilot").tag("copilot")
                    Text(english ? "Local LLM" : "ローカル LLM").tag("local")
                }
                if store.provider == "local" {
                    TextField(english ? "API base URL" : "API ベース URL", text: $store.localURL)
                    Text(english ? "Ollama or LM Studio · OpenAI-compatible endpoint on this Mac." :
                            "Ollama / LM Studio の OpenAI 互換エンドポイントを指定します。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                TextField(english ? "Model ID" : "モデル ID", text: $store.model)
                SecureField(
                    store.provider == "local"
                        ? (english ? "Token (optional)" : "トークン（任意）")
                        : (store.provider == "copilot"
                           ? (english ? "GitHub Token (optional)" : "GitHub トークン（任意）")
                           : (store.provider == "gemini_cli"
                              ? (english ? "GEMINI_API_KEY (optional)" : "GEMINI_API_KEY（任意・Google ログイン時は空欄）")
                              : "API Key")),
                    text: $store.key,
                    prompt: Text(store.keyStatus.isEmpty ? "" : store.keyStatus)
                )
                Text(
                    store.provider == "copilot"
                        ? (english
                           ? "Uses your GitHub Copilot subscription via Copilot SDK (falls back to gh CLI login if blank)."
                           : "GitHub Copilot SDK 経由でサブスクリプションを利用します（空欄時は gh CLI のログインを使用）。")
                        : (store.provider == "gemini_cli"
                           ? (english
                              ? "Runs local Antigravity CLI (agy) in read-only headless mode using your Google account login (no API key needed)."
                              : "ローカルの Antigravity CLI（agy）を読み取り専用ヘッドレスモードで実行します（Google ログイン済みなら API キー不要）。")
                           : (english
                              ? "Leave the key blank to keep the saved value."
                              : "キーを空欄にすると、保存済みの値を使用します。"))
                )
                    .font(.caption).foregroundStyle(.secondary)
            } header: {
                Text(english ? "AI connection" : "AI 接続")
            }
            if store.provider == "copilot" {
                Section {
                    HStack {
                        Label(
                            store.copilotInstalled
                                ? (english
                                   ? "Installed\(store.copilotVersion.isEmpty ? "" : " (v\(store.copilotVersion))")"
                                   : "インストール済み\(store.copilotVersion.isEmpty ? "" : " (v\(store.copilotVersion))")")
                                : (english ? "Not installed" : "未インストール"),
                            systemImage: store.copilotInstalled ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
                        )
                        .foregroundStyle(SemanticColors.role(store.copilotInstalled ? "successText" : "dangerText"))
                        Spacer()
                        Button(
                            store.copilotInstalled
                                ? (english ? "Check for Updates" : "アップデートを確認")
                                : (english ? "Install Copilot SDK" : "インストール")
                        ) {
                            store.installOrUpdateCopilotSDK(english: english)
                        }
                        .buttonStyle(.bordered)
                    }
                    if !store.copilotPythonPath.isEmpty {
                        Text(store.copilotPythonPath)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text(english ? "GitHub Copilot SDK" : "GitHub Copilot SDK ランタイム")
                }
            }
            if store.provider == "gemini_cli" {
                Section {
                    HStack {
                        Label(
                            store.geminiCliInstalled
                                ? (english
                                   ? "Installed\(store.geminiCliVersion.isEmpty ? "" : " (v\(store.geminiCliVersion))") · \(store.geminiCliAuthenticated ? "Authenticated" : "Login required")"
                                   : "インストール済み\(store.geminiCliVersion.isEmpty ? "" : " (v\(store.geminiCliVersion))") · \(store.geminiCliAuthenticated ? "認証済み" : "ログイン要確認")")
                                : (english ? "Not installed" : "未インストール"),
                            systemImage: (store.geminiCliInstalled && store.geminiCliAuthenticated) ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
                        )
                        .foregroundStyle(SemanticColors.role((store.geminiCliInstalled && store.geminiCliAuthenticated) ? "successText" : "warningText"))
                        Spacer()
                        Button(
                            store.geminiCliInstalled
                                ? (english ? "Update Antigravity CLI" : "アップデート")
                                : (english ? "Install Antigravity CLI" : "インストール")
                        ) {
                            store.installOrUpdateGeminiCli(english: english)
                        }
                        .buttonStyle(.bordered)
                    }
                    if !store.geminiCliPath.isEmpty {
                        Text(store.geminiCliPath)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    if store.geminiCliInstalled && !store.geminiCliAuthenticated {
                        HStack(spacing: 10) {
                            Button {
                                openGeminiCliLoginInTerminal()
                            } label: {
                                Label(
                                    english ? "Open Terminal to Sign In" : "ターミナルで Google ログインを開く",
                                    systemImage: "terminal"
                                )
                            }
                            .buttonStyle(.borderedProminent)
                            Button {
                                Task { await store.refreshGeminiCliStatus() }
                            } label: {
                                Label(english ? "Re-check Login" : "ログイン状態を再確認", systemImage: "arrow.clockwise")
                            }
                            .buttonStyle(.bordered)
                        }
                        Text(english
                             ? "Click the button above to launch `agy` in Terminal, sign in with Google, then click Re-check Login."
                             : "上のボタンを押すとターミナルが自動で開き `agy` が起動します。Google ログイン完了後に「ログイン状態を再確認」を押してください。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text(english ? "Antigravity CLI (agy) Runtime" : "Antigravity CLI (agy) ランタイム")
                }
            }
            Section {
                HStack {
                    Button(english ? "Save" : "保存") { store.saveAI(test: false, english: english) }
                    Button(english ? "Save and test" : "保存して接続テスト") { store.saveAI(test: true, english: english) }
                        .buttonStyle(.borderedProminent)
                }
                ConnectionFeedback(store: store)
            }
        }
        .formStyle(.grouped)
        .disabled(store.busy)
        .onChange(of: store.provider) { _, next in
            store.selectProvider()
            if next == "copilot" {
                Task { await store.refreshCopilotStatus() }
            } else if next == "gemini_cli" {
                Task { await store.refreshGeminiCliStatus() }
            }
        }
        .task { store.port = port; store.loadAI() }
    }

    private func openGeminiCliLoginInTerminal() {
        let geminiBin = store.geminiCliPath.isEmpty ? "gemini" : store.geminiCliPath
        let scriptURL = FileManager.default.temporaryDirectory.appendingPathComponent("repoaudt_gemini_login.command")
        let script = """
        #!/bin/zsh
        export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
        clear
        echo "=========================================="
        echo " RepoAUDT Mac — Gemini CLI Google Login"
        echo "=========================================="
        echo ""
        echo "Sign in with your Google account, then return to RepoAUDT Mac."
        echo ""
        "\(geminiBin)"
        code=$?
        if [ $code -ne 0 ]; then
          echo ""
          echo "gemini exited with status $code. Press Enter to close."
          read
        fi
        """
        do {
            try script.write(to: scriptURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            proc.arguments = ["-a", "Terminal", scriptURL.path]
            try proc.run()
        } catch {
            store.failed = true
            store.feedback = english
                ? "Could not launch Terminal: \(error.localizedDescription)"
                : "ターミナルを起動できませんでした: \(error.localizedDescription)"
        }
    }
}

struct ConnectionFeedback: View {
    @ObservedObject var store: ConnectionStore
    var body: some View {
        if store.busy { ProgressView().controlSize(.small) }
        if !store.feedback.isEmpty {
            Label(store.feedback, systemImage: store.failed ? "exclamationmark.octagon" : "checkmark.circle")
                .foregroundStyle(SemanticColors.role(store.failed ? "dangerText" : "successText"))
                .font(.callout).textSelection(.enabled)
        }
    }
}

struct MCPConnectionView: View {
    @StateObject private var store = ConnectionStore()
    @State private var tab = "server"
    let english: Bool
    let port: Int

    var body: some View {
        VStack(spacing: 0) {
            Picker("MCP", selection: $tab) {
                Text(english ? "Server" : "サーバー").tag("server")
                Text(english ? "Client" : "クライアント").tag("client")
            }.pickerStyle(.segmented).padding(24)
            Form {
                if tab == "server" {
                    Section(english ? "Use RepoAUDT Mac from another app" : "他のアプリから RepoAUDT Mac を使う") {
                        Text(english ? "Copy this stdio configuration into your MCP client." : "この stdio 設定を MCP クライアントに登録します。")
                            .foregroundStyle(.secondary)
                        Text(store.serverConfig.isEmpty ? "—" : store.serverConfig)
                            .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button(english ? "Copy configuration" : "設定をコピー") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(store.serverConfig, forType: .string)
                        }.disabled(store.serverConfig.isEmpty)
                        Text("HTTP JSON-RPC · http://127.0.0.1:\(String(port))/api/mcp")
                            .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                } else {
                    Section(english ? "Connect to an MCP server" : "外部 MCP サーバーへの接続") {
                        Picker(english ? "Transport" : "接続方法", selection: $store.transport) {
                            Text("stdio").tag("stdio")
                            Text("Streamable HTTP").tag("http")
                        }
                        if store.transport == "stdio" {
                            TextField(english ? "Executable" : "実行ファイル", text: $store.command)
                            TextField(english ? "Arguments (JSON array)" : "引数（JSON 配列）", text: $store.arguments, axis: .vertical)
                                .font(.system(.body, design: .monospaced))
                        } else {
                            TextField("URL", text: $store.endpoint)
                            TextField(english ? "Token environment variable" : "トークンの環境変数名", text: $store.tokenEnvironment)
                        }
                        HStack {
                            Button(english ? "Save" : "保存") { store.saveMCP(english: english) }
                            Button(english ? "Connect and list tools" : "接続してツールを取得") { store.testMCP(english: english) }
                                .buttonStyle(.borderedProminent)
                        }
                    }
                    if !store.tools.isEmpty {
                        Section(english ? "Tool execution" : "ツール実行") {
                            Picker(english ? "Tool" : "ツール", selection: $store.toolName) {
                                ForEach(store.tools) { Text($0.name).tag($0.name) }
                            }
                            if let tool = store.tools.first(where: { $0.name == store.toolName }) {
                                Text(tool.description).font(.caption).foregroundStyle(.secondary)
                                DisclosureGroup(english ? "Input schema" : "入力スキーマ") {
                                    Text(tool.schema).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                }
                            }
                            TextField(english ? "Arguments (JSON object)" : "引数（JSON オブジェクト）", text: $store.toolArguments, axis: .vertical)
                                .font(.system(.body, design: .monospaced))
                            Button(english ? "Run tool" : "ツールを実行") { store.callTool() }
                            if !store.output.isEmpty {
                                Text(store.output).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                }
                Section { ConnectionFeedback(store: store) }
            }.formStyle(.grouped)
        }
        .disabled(store.busy)
        .onChange(of: store.transport) { _, _ in store.tools = []; store.output = "" }
        .onChange(of: store.command) { _, _ in store.tools = [] }
        .onChange(of: store.arguments) { _, _ in store.tools = [] }
        .onChange(of: store.endpoint) { _, _ in store.tools = [] }
        .onChange(of: store.tokenEnvironment) { _, _ in store.tools = [] }
        .task { store.port = port; store.loadMCP() }
    }
}

struct ScannerDiagnostic: Identifiable {
    let id: String
    let label: String
    let installed: Bool
    let path: String
    let version: String
    let installHint: String
    var updateAvailable: Bool = false
    var latestVersion: String = ""
}

struct SystemUpdateView: View {
    @StateObject private var store = ConnectionStore()
    @State private var pythonPath = ""
    @State private var pythonVersion = ""
    @State private var ghPath = ""
    @State private var ghAuthenticated = false
    @State private var ghUpdateAvailable = false
    @State private var ghLatestVersion = ""
    @State private var copilotUpdateAvailable = false
    @State private var copilotLatestVersion = ""
    @State private var repoDir = ""
    @State private var localCommit = ""
    @State private var dirtyRepo = false
    @State private var scanners: [ScannerDiagnostic] = []
    @State private var upgradingTool: String? = nil
    @State private var logText = ""
    @State private var updateAvailable = false
    @State private var remoteCommit = ""
    @State private var behindCount = 0
    let english: Bool
    let port: Int
    @Binding var autoRunUpdate: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(english ? "Runtime & App Update" : "実行環境の診断・アップデート")
                        .font(.title2.bold())
                    Text(english
                         ? "Check Python, GitHub CLI, Copilot SDK, 7 CLI security scanners, and update RepoAUDT Mac from GitHub."
                         : "Python・GitHub CLI・Copilot SDK・7 種の CLI セキュリティスキャナの状態確認と、GitHub からのアプリ更新を行います。")
                        .foregroundStyle(.secondary)
                }

                GroupBox {
                    VStack(spacing: 0) {
                        diagnosticRow(
                            ok: !pythonPath.isEmpty,
                            title: "Python 3",
                            detail: pythonPath.isEmpty ? "-" : "\(pythonPath) (\(pythonVersion))"
                        )
                        Divider()
                        HStack(spacing: 12) {
                            Image(systemName: (!ghPath.isEmpty && ghAuthenticated) ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(SemanticColors.role((!ghPath.isEmpty && ghAuthenticated) ? "successText" : "dangerText"))
                            Text("GitHub CLI (gh)")
                                .font(.body.weight(.medium))
                            Spacer()
                            Text(ghPath.isEmpty
                                 ? (english ? "Not installed" : "未インストール")
                                 : (ghAuthenticated ? "\(ghPath) · \(english ? "Logged in" : "ログイン済み")" : "\(ghPath) · \(english ? "Not logged in" : "未ログイン")"))
                                .font(.callout.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            if ghUpdateAvailable && !ghLatestVersion.isEmpty {
                                Text("→ \(ghLatestVersion)")
                                    .font(.caption.monospaced().weight(.semibold))
                                    .foregroundStyle(SemanticColors.role("actionText"))
                            }
                            if upgradingTool == "gh" {
                                ProgressView().controlSize(.small)
                            } else if ghPath.isEmpty || ghUpdateAvailable {
                                Button(ghPath.isEmpty
                                       ? (english ? "Install" : "導入")
                                       : (english ? "Update" : "アップデート")) {
                                    runCliToolUpgrade("gh")
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .disabled(store.busy || upgradingTool != nil)
                            }
                        }
                        .padding(.vertical, 10)
                        Divider()
                        HStack(spacing: 12) {
                            Image(systemName: store.copilotInstalled ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(SemanticColors.role(store.copilotInstalled ? "successText" : "dangerText"))
                            Text("GitHub Copilot SDK")
                                .font(.body.weight(.medium))
                            Spacer()
                            Text(store.copilotInstalled
                                 ? (store.copilotVersion.isEmpty ? (english ? "Installed" : "インストール済み") : "v\(store.copilotVersion)")
                                 : (english ? "Not installed" : "未インストール"))
                                .font(.callout.monospaced())
                                .foregroundStyle(.secondary)
                            if copilotUpdateAvailable && !copilotLatestVersion.isEmpty {
                                Text("→ v\(copilotLatestVersion)")
                                    .font(.caption.monospaced().weight(.semibold))
                                    .foregroundStyle(SemanticColors.role("actionText"))
                            }
                            if !store.copilotInstalled || copilotUpdateAvailable {
                                Button(store.copilotInstalled
                                       ? (english ? "Update" : "アップデート")
                                       : (english ? "Install" : "導入")) {
                                    runCopilotInstall()
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                                .disabled(store.busy || upgradingTool != nil)
                            }
                        }
                        .padding(.vertical, 10)
                        Divider()
                        diagnosticRow(
                            ok: !repoDir.isEmpty,
                            title: english ? "Local Git Repository" : "ローカル Git リポジトリ",
                            detail: repoDir.isEmpty
                                ? (english ? "Not found" : "見つかりません")
                                : "\(repoDir) (\(localCommit)\(dirtyRepo ? (english ? " · uncommitted changes" : " · 未コミット変更あり") : ""))"
                        )
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
                }

                if !scanners.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(english ? "Security Scanners (CLI Engines)" : "セキュリティスキャナ（CLI エンジン）")
                            .font(.headline)
                        GroupBox {
                            VStack(spacing: 0) {
                                ForEach(Array(scanners.enumerated()), id: \.element.id) { idx, sc in
                                    if idx > 0 { Divider() }
                                    HStack(spacing: 12) {
                                        Image(systemName: sc.installed ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                            .foregroundStyle(SemanticColors.role(sc.installed ? "successText" : "dangerText"))
                                        Text(sc.label)
                                            .font(.body.weight(.medium))
                                        Spacer()
                                        Text(sc.installed
                                             ? (sc.version.isEmpty ? sc.path : "\(sc.version) · \(sc.path)")
                                             : (english ? "Not installed (\(sc.installHint))" : "未導入（\(sc.installHint)）"))
                                            .font(.callout.monospaced())
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                            .truncationMode(.middle)
                                        if sc.updateAvailable && !sc.latestVersion.isEmpty {
                                            Text("→ \(sc.latestVersion)")
                                                .font(.caption.monospaced().weight(.semibold))
                                                .foregroundStyle(SemanticColors.role("actionText"))
                                        }
                                        if upgradingTool == sc.id {
                                            ProgressView().controlSize(.small)
                                        } else if !sc.installed || sc.updateAvailable {
                                            Button(sc.installed
                                                   ? (english ? "Update" : "アップデート")
                                                   : (english ? "Install" : "導入")) {
                                                runCliToolUpgrade(sc.id)
                                            }
                                            .buttonStyle(.bordered)
                                            .controlSize(.small)
                                            .disabled(store.busy || upgradingTool != nil)
                                        }
                                    }
                                    .padding(.vertical, 10)
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 4)
                        }
                    }
                }

                HStack(spacing: 12) {
                    Button {
                        Task { await loadDiagnosticsAndCheckUpdate(autoUpdate: false) }
                    } label: {
                        Label(english ? "Re-check" : "再診断", systemImage: "arrow.clockwise")
                    }
                    .disabled(store.busy)

                    Button {
                        Task { await loadDiagnosticsAndCheckUpdate(autoUpdate: true) }
                    } label: {
                        Label(english ? "Update App" : "アプリをアップデート", systemImage: "arrow.down.circle")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(store.busy)

                    if store.busy {
                        ProgressView()
                            .controlSize(.small)
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text(english ? "Log" : "ログ")
                        .font(.headline)
                    ScrollView {
                        Text(logText.isEmpty ? (english ? "Ready." : "待機中...") : logText)
                            .font(.system(.callout, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                            .padding(12)
                    }
                    .frame(minHeight: 160, maxHeight: 260)
                    .background(Color(nsColor: .textBackgroundColor).opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.6)))
                }
            }
            .padding(28)
            .frame(maxWidth: 960, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .task {
            store.port = port
            let shouldUpdate = autoRunUpdate
            autoRunUpdate = false
            await loadDiagnosticsAndCheckUpdate(autoUpdate: shouldUpdate)
        }
        .onChange(of: autoRunUpdate) { _, shouldUpdate in
            guard shouldUpdate else { return }
            autoRunUpdate = false
            Task { await loadDiagnosticsAndCheckUpdate(autoUpdate: true) }
        }
    }

    @ViewBuilder
    private func diagnosticRow(ok: Bool, title: String, detail: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(SemanticColors.role(ok ? "successText" : "dangerText"))
            Text(title)
                .font(.body.weight(.medium))
            Spacer()
            Text(detail)
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.vertical, 10)
    }

    private func appendLog(_ line: String) {
        if logText.isEmpty {
            logText = line
        } else {
            logText += "\n" + line
        }
    }

    private func runCopilotInstall() {
        store.busy = true
        appendLog(english ? "Installing/updating github-copilot-sdk..." : "github-copilot-sdk を導入/更新中...")
        Task {
            defer { store.busy = false }
            do {
                let res = try await store.request("/api/connections/copilot/install", body: [:])
                store.copilotInstalled = res["sdk_installed"] as? Bool ?? false
                store.copilotVersion = res["sdk_version"] as? String ?? ""
                appendLog("github-copilot-sdk v\(store.copilotVersion) ready.")
            } catch {
                appendLog("Error: \(error.localizedDescription)")
            }
        }
    }

    private func runCliToolUpgrade(_ tool: String) {
        guard !store.busy, upgradingTool == nil else { return }
        upgradingTool = tool
        appendLog(english ? "Updating \(tool) via Homebrew..." : "Homebrew で \(tool) をアップデートしています…")
        Task {
            defer { upgradingTool = nil }
            do {
                let res = try await store.request("/api/app/tool/upgrade", body: ["tool": tool])
                if let out = res["log"] as? String, !out.isEmpty {
                    appendLog(out)
                }
                if let diag = res["diagnostics"] as? [String: Any] {
                    ghPath = diag["gh_path"] as? String ?? ghPath
                    ghAuthenticated = diag["gh_authenticated"] as? Bool ?? ghAuthenticated
                    ghUpdateAvailable = diag["gh_update_available"] as? Bool ?? false
                    ghLatestVersion = diag["gh_latest_version"] as? String ?? ""
                    let rawScanners = diag["scanners"] as? [[String: Any]] ?? []
                    scanners = rawScanners.map { sc in
                        ScannerDiagnostic(
                            id: sc["name"] as? String ?? UUID().uuidString,
                            label: sc["label"] as? String ?? (sc["name"] as? String ?? "Scanner"),
                            installed: sc["installed"] as? Bool ?? false,
                            path: sc["path"] as? String ?? "",
                            version: sc["version"] as? String ?? "",
                            installHint: sc["install_hint"] as? String ?? "",
                            updateAvailable: sc["update_available"] as? Bool ?? false,
                            latestVersion: sc["latest_version"] as? String ?? ""
                        )
                    }
                }
                appendLog(english ? "\(tool) updated successfully." : "\(tool) のアップデートが完了しました。")
            } catch {
                appendLog("Error (\(tool)): \(error.localizedDescription)")
            }
        }
    }

    private func loadDiagnosticsAndCheckUpdate(autoUpdate: Bool) async {
        guard !store.busy else { return }
        store.busy = true
        defer { store.busy = false }

        do {
            let diag = try await store.request("/api/app/diagnostics")
            pythonPath = diag["python_executable"] as? String ?? ""
            pythonVersion = diag["python_version"] as? String ?? ""
            ghPath = diag["gh_path"] as? String ?? ""
            ghAuthenticated = diag["gh_authenticated"] as? Bool ?? false
            ghUpdateAvailable = diag["gh_update_available"] as? Bool ?? false
            ghLatestVersion = diag["gh_latest_version"] as? String ?? ""
            store.copilotInstalled = diag["copilot_sdk_installed"] as? Bool ?? false
            store.copilotVersion = diag["copilot_sdk_version"] as? String ?? ""
            copilotUpdateAvailable = diag["copilot_sdk_update_available"] as? Bool ?? false
            copilotLatestVersion = diag["copilot_sdk_latest_version"] as? String ?? ""
            let repo = diag["repo"] as? [String: Any] ?? [:]
            repoDir = repo["repo_dir"] as? String ?? ""
            localCommit = repo["local_commit"] as? String ?? ""
            dirtyRepo = repo["dirty"] as? Bool ?? false
            let rawScanners = diag["scanners"] as? [[String: Any]] ?? []
            scanners = rawScanners.map { sc in
                ScannerDiagnostic(
                    id: sc["name"] as? String ?? UUID().uuidString,
                    label: sc["label"] as? String ?? (sc["name"] as? String ?? "Scanner"),
                    installed: sc["installed"] as? Bool ?? false,
                    path: sc["path"] as? String ?? "",
                    version: sc["version"] as? String ?? "",
                    installHint: sc["install_hint"] as? String ?? "",
                    updateAvailable: sc["update_available"] as? Bool ?? false,
                    latestVersion: sc["latest_version"] as? String ?? ""
                )
            }

            if autoUpdate {
                appendLog("Updating RepoAUDT Mac from \(repoDir.isEmpty ? "~/Git/RepoAUDT-Mac" : repoDir)...")
            }
            let check = try await store.request("/api/app/update/check")
            if let log = check["log"] as? String, !log.isEmpty {
                logText = log
            }
            updateAvailable = check["update_available"] as? Bool ?? false
            remoteCommit = check["remote_commit"] as? String ?? ""
            behindCount = check["behind_count"] as? Int ?? 0

            if autoUpdate {
                if !updateAvailable {
                    return
                }
                if dirtyRepo {
                    appendLog(english
                              ? "Skipped auto-update: local uncommitted changes exist."
                              : "未コミットの変更があるため自動アップデートをスキップしました。")
                    return
                }
                appendLog(english
                          ? "Pulling origin/main, rebuilding, and relaunching..."
                          : "origin/main を取得してビルド・再起動を開始します...")
                _ = try await store.request("/api/app/update/apply", body: [:])
                appendLog(english
                          ? "Update started in background. RepoAUDT Mac will relaunch automatically."
                          : "バックグラウンドでアップデートを開始しました。完了後に自動で再起動します。")
            }
        } catch {
            appendLog("Error: \(error.localizedDescription)")
        }
    }
}
