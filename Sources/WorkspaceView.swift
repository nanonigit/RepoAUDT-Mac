import AppKit
import SwiftUI

struct WorkspaceRepository: Decodable, Identifiable {
    let id: String
    let name: String
    let url: String
    let commit: String
    let description: String
    let findings: Int
    let severity: String
}

struct WorkspaceSnapshot: Decodable {
    let repositories: [WorkspaceRepository]
    let selectedID: String?
    let page: String?
}

enum WorkspacePage: String, CaseIterable, Identifiable {
    case dashboard, audit, architecture, sequence, ai, mcp

    var id: String { rawValue }
    var command: String {
        switch self {
        case .dashboard, .audit: return "coderabbit"
        case .architecture: return "arch"
        case .sequence: return "seq"
        case .ai, .mcp: return ""
        }
    }
    var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .audit: return "checkmark.shield"
        case .architecture: return "square.3.layers.3d"
        case .sequence: return "point.3.connected.trianglepath.dotted"
        case .ai: return "brain"
        case .mcp: return "point.3.filled.connected.trianglepath.dotted"
        }
    }
    func title(english: Bool) -> String {
        switch self {
        case .dashboard: return english ? "Dashboard" : "ダッシュボード"
        case .audit: return english ? "Audit results" : "監査結果"
        case .architecture: return english ? "Architecture" : "構成図"
        case .sequence: return english ? "Execution flows" : "実行フロー"
        case .ai: return english ? "AI connections" : "AI 接続"
        case .mcp: return "MCP"
        }
    }
}

struct MainContentView: View {
    @ObservedObject var backend = BackendServerManager.shared
    @ObservedObject var coordinator: WebViewCoordinator
    @AppStorage("workspaceLanguage") private var language = "ja"
    @State private var selection: String? = WorkspacePage.dashboard.rawValue
    @State private var query = ""

    private var nativePage: Bool { [.dashboard, .ai, .mcp].contains(page) }
    private var english: Bool { language == "en" }
    private var page: WorkspacePage { coordinator.page }
    private var repositories: [WorkspaceRepository] {
        coordinator.repositories.filter {
            query.isEmpty || $0.name.localizedCaseInsensitiveContains(query)
        }
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section(english ? "Workspace" : "ワークスペース") {
                    ForEach([WorkspacePage.dashboard, .audit, .architecture, .sequence]) { item in
                        Label(item.title(english: english), systemImage: item.symbol)
                            .tag(item.rawValue)
                    }
                }
                Section(english ? "Connections" : "接続") {
                    Label(english ? "AI connections" : "AI 接続", systemImage: "brain").tag(WorkspacePage.ai.rawValue)
                    Label("MCP", systemImage: "point.3.filled.connected.trianglepath.dotted").tag(WorkspacePage.mcp.rawValue)
                }
                Section(english ? "Repositories" : "リポジトリ") {
                    ForEach(repositories) { repo in
                        Label(repo.name, systemImage: "folder")
                            .lineLimit(1)
                            .help(repo.name)
                            .tag("repo:" + repo.id)
                    }
                }
            }
            .listStyle(.sidebar)
            .searchable(text: $query, placement: .sidebar,
                        prompt: english ? "Find repositories" : "リポジトリを検索")
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: 6) {
                    Button {
                        showPage(.audit)
                        coordinator.send("settings")
                    } label: {
                        Label(english ? "Settings" : "設定", systemImage: "gearshape")
                    }
                    .buttonStyle(.plain)
                    .padding(.bottom, 8)
                    Label(coordinator.ready ? (english ? "Local engine" : "ローカル解析エンジン") :
                            (english ? "Loading" : "読み込み中"),
                          systemImage: coordinator.ready ? "desktopcomputer" : "hourglass")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("RepoAUDT Mac").font(.caption2).foregroundStyle(.tertiary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                .background(.bar)
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 240, max: 320)
        } detail: {
            ZStack {
                Color(nsColor: .windowBackgroundColor)
                if backend.isReady, let url = URL(string: "http://127.0.0.1:\(backend.port)/index.html") {
                    PortalWebView(url: url, coordinator: coordinator)
                        .opacity(nativePage || !coordinator.ready ? 0 : 1)
                        .allowsHitTesting(!nativePage && coordinator.ready)
                        .accessibilityHidden(nativePage || !coordinator.ready)
                }
                if !coordinator.ready {
                    loadingView
                } else if page == .dashboard {
                    dashboard
                } else if page == .ai {
                    AIConnectionView(english: english, port: backend.port)
                } else if page == .mcp {
                    MCPConnectionView(english: english, port: backend.port)
                }
            }
            .navigationTitle(page.title(english: english))
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    if !nativePage {
                        Button {
                            coordinator.send("details")
                        } label: {
                            Label(english ? "Details" : "詳細", systemImage: "sidebar.right")
                        }
                        .help(english ? "Show or hide details" : "詳細を表示・非表示")
                        .disabled(!coordinator.ready)
                    }
                    Button {
                        showPage(.audit)
                        coordinator.send("analyze")
                    } label: {
                        Label(english ? "Add repository" : "リポジトリを追加", systemImage: "plus")
                    }
                    .help(english ? "Analyze a GitHub URL" : "GitHub URL を指定して解析")
                    .disabled(!coordinator.ready)
                    Picker(english ? "Language" : "言語", selection: $language) {
                        Text("日本語").tag("ja")
                        Text("English").tag("en")
                    }
                    .labelsHidden()
                    .frame(width: 105)
                    .help(english ? "Display language" : "表示言語")
                }
            }
        }
        .tint(SemanticColors.role("action"))
        .onChange(of: selection) { _, value in
            guard let value else { return }
            if let next = WorkspacePage(rawValue: value) {
                coordinator.page = next
                coordinator.send("page", value: next.command)
            } else if value.hasPrefix("repo:") {
                coordinator.page = .audit
                coordinator.send("repository", value: String(value.dropFirst(5)))
                coordinator.send("page", value: WorkspacePage.audit.command)
            }
        }
        .onChange(of: coordinator.page) { _, value in
            if value != .audit || selection?.hasPrefix("repo:") != true {
                selection = value.rawValue
            }
        }
        .onChange(of: language) { _, value in
            coordinator.language = value
            coordinator.send("language", value: value)
        }
        .onAppear { coordinator.language = language }
    }

    private func showPage(_ next: WorkspacePage) {
        coordinator.page = next
        selection = next.rawValue
        coordinator.send("page", value: next.command)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            if let error = coordinator.loadError {
                Image(systemName: "exclamationmark.octagon").font(.largeTitle).foregroundStyle(SemanticColors.role("dangerText"))
                Text(english ? "Could not load the workspace" : "ワークスペースを読み込めません")
                    .font(.title2.bold())
                Text(error).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                Button(english ? "Try again" : "再試行") { coordinator.reload() }
            } else {
                ProgressView()
                Text(english ? "Loading saved analyses…" : "保存済みの解析を読み込み中…")
                    .foregroundStyle(.secondary)
            }
        }
        .padding(32)
    }

    private var dashboard: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(english ? "Understand your code. Plan the next fix." : "コードを把握して、次の修正へ")
                        .font(.title.bold())
                    Text(english ? "Review saved analyses or add a GitHub repository." :
                            "保存済みの解析を確認するか、GitHub リポジトリを追加してください。")
                        .font(.body).foregroundStyle(.secondary)
                }
                GroupBox {
                    HStack(spacing: 20) {
                        Image(systemName: "checkmark.shield").font(.system(size: 32)).foregroundStyle(SemanticColors.role("actionText"))
                        VStack(alignment: .leading, spacing: 6) {
                            Text(english ? "Start with a GitHub URL" : "GitHub URL から解析を始める")
                                .font(.headline)
                            Text(english ? "Inspect findings, code structure and execution flows in one workspace." :
                                    "監査結果・コードの構成・実行フローをひとつの場所で確認できます。")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                        Button(english ? "Add repository" : "リポジトリを追加") {
                            showPage(.audit)
                            coordinator.send("analyze")
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding(18)
                }
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text(english ? "Saved analyses" : "保存済みの解析").font(.headline)
                        Text("\(coordinator.repositories.count)").foregroundStyle(.secondary)
                        Spacer()
                        Button {
                            coordinator.send("refresh")
                        } label: {
                            Label(english ? "Reload list" : "一覧を更新", systemImage: "arrow.clockwise")
                        }
                    }
                    if repositories.isEmpty {
                        ContentUnavailableView(
                            query.isEmpty ? (english ? "No saved analyses" : "保存済みの解析はありません") :
                                (english ? "No matching repositories" : "一致するリポジトリはありません"),
                            systemImage: query.isEmpty ? "folder.badge.plus" : "magnifyingglass",
                            description: Text(query.isEmpty ?
                                (english ? "Add a GitHub URL to begin." : "GitHub URL を追加して始めましょう。") :
                                (english ? "Try another search." : "検索語を変更してください。")))
                    } else {
                        VStack(spacing: 0) {
                            ForEach(repositories) { repo in
                                repositoryRow(repo)
                                if repo.id != repositories.last?.id { Divider().padding(.leading, 48) }
                            }
                        }
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator.opacity(0.5)))
                    }
                    Text(english ? "Counts reflect saved findings. Open a repository to inspect evidence and scan details." :
                            "件数は保存済みの指摘です。根拠や解析の詳細は各リポジトリで確認できます。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(32)
            .frame(maxWidth: 1100, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    private func repositoryRow(_ repo: WorkspaceRepository) -> some View {
        Button {
            selection = "repo:" + repo.id
            coordinator.page = .audit
            coordinator.send("repository", value: repo.id)
            coordinator.send("page", value: WorkspacePage.audit.command)
        } label: {
            HStack(spacing: 14) {
                Image(systemName: "folder").font(.title3).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 5) {
                    Text(repo.name).font(.body.weight(.medium)).lineLimit(1)
                    Text(repo.commit.isEmpty ? (english ? "Commit not recorded" : "コミット未記録") : String(repo.commit.prefix(10)))
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer(minLength: 10)
                Label(english ? "\(repo.findings) findings" : "指摘 \(repo.findings)件",
                      systemImage: SemanticColors.severitySymbol(repo.severity))
                    .font(.callout).foregroundStyle(SemanticColors.severityColor(repo.severity))
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .padding(16)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(english ? "Open saved audit for \(repo.name)" : "\(repo.name) の監査結果を開く")
    }
}
