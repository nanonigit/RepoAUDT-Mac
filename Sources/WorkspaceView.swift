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
    let updatedAt: String?
    let analyzedAt: String?
}

enum RepositorySortOrder: String, CaseIterable, Identifiable {
    case defaultOrder
    case nameAsc
    case nameDesc
    case updatedDesc
    case findingsDesc
    case severityDesc

    var id: String { rawValue }

    func title(english: Bool) -> String {
        switch self {
        case .defaultOrder: return english ? "Default order" : "保存順"
        case .nameAsc: return english ? "Name (A–Z)" : "名前順 (A → Z)"
        case .nameDesc: return english ? "Name (Z–A)" : "名前順 (Z → A)"
        case .updatedDesc: return english ? "Recently updated" : "変更・更新が新しい順"
        case .findingsDesc: return english ? "Most findings" : "指摘件数が多い順"
        case .severityDesc: return english ? "Highest severity" : "重要度が高い順"
        }
    }
}

enum DashboardSortOrder: String, CaseIterable, Identifiable {
    case severityDesc
    case severityAsc
    case analyzedDesc
    case analyzedAsc
    case byRepository
    case nameAsc
    case nameDesc

    var id: String { rawValue }

    func title(english: Bool) -> String {
        switch self {
        case .severityDesc: return english ? "Highest risk first" : "危険度の高い順"
        case .severityAsc: return english ? "Lowest risk first" : "安全な順（危険度が低い順）"
        case .analyzedDesc: return english ? "Analyzed (newest)" : "解析日時が新しい順"
        case .analyzedAsc: return english ? "Analyzed (oldest)" : "解析日時が古い順"
        case .byRepository: return english ? "By repository" : "リポジトリごと"
        case .nameAsc: return english ? "Name (A–Z)" : "名前順 (A → Z)"
        case .nameDesc: return english ? "Name (Z–A)" : "名前順 (Z → A)"
        }
    }
}

struct WorkspaceSnapshot: Decodable {
    let repositories: [WorkspaceRepository]
    let selectedID: String?
    let page: String?
}

enum WorkspacePage: String, CaseIterable, Identifiable {
    case dashboard, audit, chat, architecture, sequence, ai, mcp, system

    var id: String { rawValue }
    var command: String {
        switch self {
        case .dashboard, .audit: return "coderabbit"
        case .chat: return "chat"
        case .architecture: return "arch"
        case .sequence: return "seq"
        case .ai, .mcp, .system: return ""
        }
    }
    var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2"
        case .audit: return "checkmark.shield"
        case .chat: return "bubble.left.and.bubble.right"
        case .architecture: return "square.3.layers.3d"
        case .sequence: return "point.3.connected.trianglepath.dotted"
        case .ai: return "brain"
        case .mcp: return "point.3.filled.connected.trianglepath.dotted"
        case .system: return "wrench.and.screwdriver"
        }
    }
    func title(english: Bool) -> String {
        switch self {
        case .dashboard: return english ? "Dashboard" : "ダッシュボード"
        case .audit: return english ? "Audit results" : "監査結果"
        case .chat: return english ? "Chat" : "チャット"
        case .architecture: return english ? "Architecture" : "構成図"
        case .sequence: return english ? "Execution flows" : "実行フロー"
        case .ai: return english ? "AI connections" : "AI 接続"
        case .mcp: return "MCP"
        case .system: return english ? "System & Update" : "実行環境・更新"
        }
    }
}

struct MainContentView: View {
    @ObservedObject var backend = BackendServerManager.shared
    @ObservedObject var coordinator: WebViewCoordinator
    @AppStorage("workspaceLanguage") private var language = "ja"
    @AppStorage("repositorySortOrder") private var sortOrderRaw = RepositorySortOrder.defaultOrder.rawValue
    @AppStorage("dashboardSortOrder") private var dashboardSortOrderRaw = DashboardSortOrder.severityDesc.rawValue
    @AppStorage("dashboardPageSize") private var dashboardPageSize = 10
    @AppStorage("repositoriesSectionExpanded") private var repositoriesExpanded = true
    @State private var selection: Set<String> = [WorkspacePage.dashboard.rawValue]
    @State private var query = ""
    @State private var dashboardPageIndex = 0
    @State private var busyRepoIDs: Set<String> = []
    @State private var reposPendingDeletion: [WorkspaceRepository] = []
    @State private var repoActionError: String?
    @State private var checkingAppUpdate = false
    @State private var applyingAppUpdate = false
    @State private var appUpdatePrompt: AppUpdateInfo?
    @State private var appUpdateStatusMessage: String?
    @State private var refreshingList = false
    @State private var listRefreshNote = ""
    @State private var didInitializeLaunchPage = false
    @State private var triggerSidebarAppUpdate = false
    @State private var headerCommit = ""
    @State private var lastUpdateCheckLabel = ""
    @State private var githubConnectionIssue: String?
    @State private var githubConnectionGuide: String?
    @State private var checkingGithubHealth = false

    private struct AppUpdateInfo {
        let localCommit: String
        let remoteCommit: String
        let behindCount: Int
        let latestMessage: String
        let dirty: Bool
    }

    private var hasSelectedRepository: Bool {
        selection.contains(where: { $0.hasPrefix("repo:") })
    }
    private var nativePage: Bool {
        [.dashboard, .ai, .mcp, .system].contains(page) || (page == .audit && !hasSelectedRepository)
    }
    private var english: Bool { language == "en" }
    private var page: WorkspacePage { coordinator.page }
    private var sortOrder: RepositorySortOrder {
        RepositorySortOrder(rawValue: sortOrderRaw) ?? .defaultOrder
    }
    private var dashboardSortOrder: DashboardSortOrder {
        DashboardSortOrder(rawValue: dashboardSortOrderRaw) ?? .severityDesc
    }
    private var repositories: [WorkspaceRepository] {
        let filtered = coordinator.repositories.filter {
            query.isEmpty || $0.name.localizedCaseInsensitiveContains(query)
        }
        return sortRepositories(filtered, by: sortOrder)
    }
    private var dashboardRepositories: [WorkspaceRepository] {
        let filtered = coordinator.repositories.filter { repo in
            query.isEmpty || repo.name.localizedCaseInsensitiveContains(query)
        }
        return sortDashboardRepositories(filtered, by: dashboardSortOrder)
    }
    private var dashboardPageCount: Int {
        let size = max(10, dashboardPageSize)
        return max(1, Int(ceil(Double(dashboardRepositories.count) / Double(size))))
    }
    private var pagedDashboardRepositories: [WorkspaceRepository] {
        let items = dashboardRepositories
        let size = max(10, dashboardPageSize)
        let safePage = min(max(0, dashboardPageIndex), max(0, dashboardPageCount - 1))
        let start = safePage * size
        guard start < items.count else { return [] }
        let end = min(items.count, start + size)
        return Array(items[start..<end])
    }

    private func sortDashboardRepositories(_ items: [WorkspaceRepository], by order: DashboardSortOrder) -> [WorkspaceRepository] {
        switch order {
        case .severityDesc:
            return items.sorted {
                let lhs = severityRank($0.severity)
                let rhs = severityRank($1.severity)
                if lhs != rhs { return lhs > rhs }
                if $0.findings != $1.findings { return $0.findings > $1.findings }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        case .severityAsc:
            return items.sorted {
                let lhs = severityRank($0.severity)
                let rhs = severityRank($1.severity)
                if lhs != rhs { return lhs < rhs }
                if $0.findings != $1.findings { return $0.findings < $1.findings }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        case .analyzedDesc:
            return items.sorted {
                let lhs = normalizedTimestamp($0.analyzedAt)
                let rhs = normalizedTimestamp($1.analyzedAt)
                if lhs != rhs { return lhs > rhs }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        case .analyzedAsc:
            return items.sorted {
                let lhs = normalizedTimestamp($0.analyzedAt)
                let rhs = normalizedTimestamp($1.analyzedAt)
                if lhs != rhs { return lhs < rhs }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        case .byRepository:
            return items.sorted {
                let lKey = ($0.url.isEmpty ? $0.name : $0.url).lowercased()
                let rKey = ($1.url.isEmpty ? $1.name : $1.url).lowercased()
                if lKey != rKey { return lKey.localizedStandardCompare(rKey) == .orderedAscending }
                return normalizedTimestamp($0.analyzedAt) > normalizedTimestamp($1.analyzedAt)
            }
        case .nameAsc:
            return items.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case .nameDesc:
            return items.sorted { $0.name.localizedStandardCompare($1.name) == .orderedDescending }
        }
    }

    private func sortRepositories(_ items: [WorkspaceRepository], by order: RepositorySortOrder) -> [WorkspaceRepository] {
        switch order {
        case .defaultOrder:
            return items
        case .nameAsc:
            return items.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case .nameDesc:
            return items.sorted { $0.name.localizedStandardCompare($1.name) == .orderedDescending }
        case .updatedDesc:
            return items.sorted {
                let lhs = normalizedTimestamp($0.updatedAt)
                let rhs = normalizedTimestamp($1.updatedAt)
                if lhs != rhs { return lhs > rhs }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        case .findingsDesc:
            return items.sorted {
                if $0.findings != $1.findings { return $0.findings > $1.findings }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        case .severityDesc:
            return items.sorted {
                let lhs = severityRank($0.severity)
                let rhs = severityRank($1.severity)
                if lhs != rhs { return lhs > rhs }
                if $0.findings != $1.findings { return $0.findings > $1.findings }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
        }
    }

    private func severityRank(_ severity: String) -> Int {
        switch severity.lowercased() {
        case "critical": return 5
        case "high": return 4
        case "medium", "warning": return 3
        case "low": return 2
        case "info": return 1
        default: return 0
        }
    }

    private func normalizedTimestamp(_ raw: String?) -> String {
        guard let raw, !raw.isEmpty else { return "" }
        // Normalize "YYYY/MM/DD HH:MM:SS" and ISO-8601 strings to lexicographically comparable format.
        return raw.replacingOccurrences(of: "/", with: "-")
    }

    private func formattedAnalysisDate(_ raw: String?) -> String? {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return nil
        }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let isoNoFrac = ISO8601DateFormatter()
        isoNoFrac.formatOptions = [.withInternetDateTime]

        let out = DateFormatter()
        out.dateFormat = "yyyy/MM/dd HH:mm"
        out.timeZone = .current

        if let date = iso.date(from: raw) ?? isoNoFrac.date(from: raw) {
            return out.string(from: date)
        }
        let slashFmt = DateFormatter()
        slashFmt.dateFormat = "yyyy/MM/dd HH:mm:ss"
        slashFmt.timeZone = .current
        if let date = slashFmt.date(from: raw) {
            return out.string(from: date)
        }
        return String(raw.prefix(16))
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Section(english ? "Workspace" : "ワークスペース") {
                    ForEach([WorkspacePage.dashboard, .audit, .chat, .architecture, .sequence]) { item in
                        Label(item.title(english: english), systemImage: item.symbol)
                            .tag(item.rawValue)
                    }
                }
                Section(english ? "Connections" : "接続") {
                    Label(english ? "AI connections" : "AI 接続", systemImage: "brain").tag(WorkspacePage.ai.rawValue)
                    Label("MCP", systemImage: "point.3.filled.connected.trianglepath.dotted").tag(WorkspacePage.mcp.rawValue)
                }
                Section(english ? "System" : "システム") {
                    Label(english ? "Runtime & Update" : "実行環境・更新", systemImage: "wrench.and.screwdriver").tag(WorkspacePage.system.rawValue)
                }
                Section {
                    if repositoriesExpanded {
                        ForEach(repositories) { repo in
                            HStack(spacing: 6) {
                                Label(repo.name, systemImage: "folder")
                                    .lineLimit(1)
                                if busyRepoIDs.contains(repo.id) {
                                    Spacer(minLength: 4)
                                    ProgressView()
                                        .controlSize(.small)
                                }
                            }
                            .help(repo.name)
                            .tag("repo:" + repo.id)
                            .contextMenu {
                                repositoryContextMenu(for: repo)
                            }
                        }
                    }
                } header: {
                    repositoriesSectionHeader
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
                    Button {
                        triggerSidebarAppUpdate = true
                        showPage(.system)
                    } label: {
                        Label(english ? "Update App" : "アプリをアップデート", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(.plain)
                    .disabled(!backend.isReady)
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
                } else if page == .audit && !hasSelectedRepository {
                    auditListView
                } else if page == .ai {
                    AIConnectionView(english: english, port: backend.port)
                } else if page == .mcp {
                    MCPConnectionView(english: english, port: backend.port)
                } else if page == .system {
                    SystemUpdateView(english: english, port: backend.port, autoRunUpdate: $triggerSidebarAppUpdate)
                }
            }
            .navigationTitle(page.title(english: english))
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    if page == .audit && hasSelectedRepository {
                        Button {
                            selection = [WorkspacePage.audit.rawValue]
                        } label: {
                            Label(english ? "All Repositories" : "一覧へ戻る", systemImage: "list.bullet")
                        }
                        .help(english ? "Back to saved analyses list" : "保存済みの解析一覧に戻る")
                    }
                    if !nativePage && page != .chat {
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
        .onChange(of: selection) { oldValue, newValue in
            let added = newValue.subtracting(oldValue)
            if let pageTag = added.first(where: { WorkspacePage(rawValue: $0) != nil }),
               let next = WorkspacePage(rawValue: pageTag) {
                if newValue.count > 1 {
                    selection = [pageTag]
                }
                coordinator.page = next
                coordinator.send("page", value: next.command)
                return
            }

            let repoTags = newValue.filter { $0.hasPrefix("repo:") }
            if !repoTags.isEmpty, newValue.contains(where: { WorkspacePage(rawValue: $0) != nil }) {
                selection = repoTags
                return
            }

            if let repoTag = added.first(where: { $0.hasPrefix("repo:") }) ?? (repoTags.count == 1 ? repoTags.first : nil) {
                coordinator.page = .audit
                coordinator.send("repository", value: String(repoTag.dropFirst(5)))
                coordinator.send("page", value: WorkspacePage.audit.command)
            }
        }
        .onChange(of: coordinator.page) { _, value in
            if value != .audit || !selection.contains(where: { $0.hasPrefix("repo:") }) {
                selection = [value.rawValue]
            }
        }
        .onChange(of: dashboardPageSize) { _, _ in
            dashboardPageIndex = 0
        }
        .onChange(of: dashboardSortOrderRaw) { _, _ in
            dashboardPageIndex = 0
        }
        .onChange(of: query) { _, _ in
            dashboardPageIndex = 0
        }
        .onChange(of: language) { _, value in
            coordinator.language = value
            coordinator.send("language", value: value)
        }
        .onAppear {
            coordinator.language = language
            if !didInitializeLaunchPage {
                didInitializeLaunchPage = true
                coordinator.page = .dashboard
                selection = [WorkspacePage.dashboard.rawValue]
            }
        }
        .confirmationDialog(
            reposPendingDeletion.count > 1
                ? (english
                   ? "Remove \(reposPendingDeletion.count) selected repositories from RepoAUDT?"
                   : "選択した \(reposPendingDeletion.count) 件のリポジトリを RepoAUDT から削除しますか？")
                : (english
                   ? "Remove \"\(reposPendingDeletion.first?.name ?? "")\" from RepoAUDT?"
                   : "「\(reposPendingDeletion.first?.name ?? "")」を RepoAUDT から削除しますか？"),
            isPresented: Binding(
                get: { !reposPendingDeletion.isEmpty },
                set: { if !$0 { reposPendingDeletion = [] } }
            ),
            titleVisibility: .visible
        ) {
            if !reposPendingDeletion.isEmpty {
                let targets = reposPendingDeletion
                Button(
                    targets.count > 1
                        ? (english ? "Remove \(targets.count) Repositories" : "\(targets.count) 件を削除")
                        : (english ? "Remove" : "削除"),
                    role: .destructive
                ) {
                    reposPendingDeletion = []
                    Task { await deleteRepositories(targets) }
                }
            }
            Button(english ? "Cancel" : "キャンセル", role: .cancel) {
                reposPendingDeletion = []
            }
        } message: {
            Text(english
                 ? "Local diagrams and audit data will be removed. Your GitHub remote repositories will not be affected."
                 : "ローカルの構成図・監査データは削除されます。GitHub 上のリモートリポジトリには影響しません。")
        }
        .alert(
            english ? "Repository Action Failed" : "リポジトリ操作に失敗しました",
            isPresented: Binding(
                get: { repoActionError != nil },
                set: { if !$0 { repoActionError = nil } }
            )
        ) {
            Button("OK", role: .cancel) { repoActionError = nil }
        } message: {
            Text(repoActionError ?? "")
        }
        .alert(
            english ? "New Version Available on GitHub" : "GitHub に新しいバージョンがあります",
            isPresented: Binding(
                get: { appUpdatePrompt != nil },
                set: { if !$0 { appUpdatePrompt = nil } }
            )
        ) {
            if let info = appUpdatePrompt, !info.dirty {
                Button(english ? "Update & Relaunch" : "アップデートして再起動") {
                    appUpdatePrompt = nil
                    Task { await applyAppUpdate() }
                }
            }
            Button(english ? "Close" : "閉じる", role: .cancel) {
                appUpdatePrompt = nil
            }
        } message: {
            if let info = appUpdatePrompt {
                if info.dirty {
                    Text(english
                         ? "\(info.behindCount) new commit(s) on origin/main (\(info.localCommit) → \(info.remoteCommit)), but local uncommitted changes exist. Commit or stash them before updating."
                         : "origin/main に \(info.behindCount) 件の更新があります（\(info.localCommit) → \(info.remoteCommit)）が、ローカルに未コミットの変更があるため自動更新できません。変更をコミットまたは退避してから再実行してください。")
                } else {
                    Text(english
                         ? "\(info.behindCount) new commit(s) (\(info.localCommit) → \(info.remoteCommit))\nLatest: \(info.latestMessage)\n\nRepoAUDT Mac will rebuild and relaunch automatically."
                         : "\(info.behindCount) 件の更新があります（\(info.localCommit) → \(info.remoteCommit)）\n最新: \(info.latestMessage)\n\n更新後にビルドして自動で再起動します。")
                }
            }
        }
        .alert(
            english ? "App Update" : "アプリのアップデート",
            isPresented: Binding(
                get: { appUpdateStatusMessage != nil },
                set: { if !$0 { appUpdateStatusMessage = nil } }
            )
        ) {
            Button("OK", role: .cancel) { appUpdateStatusMessage = nil }
        } message: {
            Text(appUpdateStatusMessage ?? "")
        }
    }

    private var repositoriesSectionHeader: some View {
        let titleText = english ? "Repositories (\(repositories.count))" : "リポジトリ (\(repositories.count))"
        let helpText = repositoriesExpanded
            ? (english ? "Collapse repositories" : "リポジトリ一覧を折りたたむ")
            : (english ? "Expand repositories" : "リポジトリ一覧を展開する")
        let sortHelp = english
            ? "Sort repositories (\(sortOrder.title(english: true)))"
            : "並び替え (\(sortOrder.title(english: false)))"
        return HStack(spacing: 6) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) {
                    repositoriesExpanded.toggle()
                }
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: repositoriesExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption2.weight(.semibold))
                    Text(titleText)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(helpText)
            Spacer()
            Menu {
                ForEach(RepositorySortOrder.allCases) { option in
                    Button {
                        sortOrderRaw = option.rawValue
                    } label: {
                        if sortOrder == option {
                            Label(option.title(english: english), systemImage: "checkmark")
                        } else {
                            Text(option.title(english: english))
                        }
                    }
                }
            } label: {
                Image(systemName: "arrow.up.arrow.down")
                    .font(.caption)
                    .foregroundStyle(sortOrder == .defaultOrder ? Color.secondary : Color.accentColor)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .help(sortHelp)
        }
    }

    private func showPage(_ next: WorkspacePage) {
        coordinator.page = next
        selection = [next.rawValue]
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

    private var appVersionLabel: String {
        let ver = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.2.0"
        return headerCommit.isEmpty ? "v\(ver)" : "v\(ver) (\(headerCommit))"
    }

    private var dashboard: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .center, spacing: 12) {
                    Text("RepoAUDT Mac")
                        .font(.title2.bold())
                    Text(appVersionLabel)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(Color.secondary.opacity(0.16), in: Capsule())
                    Spacer()
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(appVersionLabel)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                        if !lastUpdateCheckLabel.isEmpty {
                            Text(english ? "Checked: \(lastUpdateCheckLabel)" : "確認: \(lastUpdateCheckLabel)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Button {
                        triggerSidebarAppUpdate = true
                        showPage(.system)
                    } label: {
                        Label(english ? "Update" : "アップデート", systemImage: "arrow.down.circle")
                    }
                    .buttonStyle(.bordered)
                    .disabled(!backend.isReady)
                }
                .task {
                    await refreshDashboardVersionHeader()
                    await refreshGithubHealthStatus()
                }
                if let ghIssue = githubConnectionIssue {
                    GroupBox {
                        HStack(alignment: .top, spacing: 14) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.title2)
                                .foregroundStyle(SemanticColors.role("dangerText"))
                                .padding(.top, 2)
                            VStack(alignment: .leading, spacing: 6) {
                                Text(ghIssue)
                                    .font(.headline)
                                    .foregroundStyle(SemanticColors.role("dangerText"))
                                if let ghGuide = githubConnectionGuide {
                                    Text(ghGuide)
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                HStack(spacing: 10) {
                                    Button {
                                        showPage(.ai)
                                    } label: {
                                        Label(english ? "Open AI / Token Settings" : "AI・GitHub トークン設定を開く", systemImage: "key.fill")
                                    }
                                    .buttonStyle(.borderedProminent)
                                    Button {
                                        showPage(.system)
                                    } label: {
                                        Label(english ? "Check GitHub CLI" : "実行環境・GitHub CLI を確認", systemImage: "wrench.and.screwdriver")
                                    }
                                    .buttonStyle(.bordered)
                                    Button {
                                        Task { await refreshGithubHealthStatus() }
                                    } label: {
                                        if checkingGithubHealth {
                                            ProgressView().controlSize(.small)
                                        } else {
                                            Label(english ? "Retry" : "接続を再確認", systemImage: "arrow.clockwise")
                                        }
                                    }
                                    .buttonStyle(.bordered)
                                    .disabled(checkingGithubHealth)
                                }
                                .padding(.top, 4)
                            }
                            Spacer(minLength: 0)
                        }
                        .padding(14)
                    }
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

                let allRepos = coordinator.repositories
                let totalFindings = allRepos.reduce(0) { $0 + $1.findings }
                let highRiskRepos = allRepos.filter { severityRank($0.severity) >= 4 }
                let highRiskFindings = highRiskRepos.reduce(0) { $0 + $1.findings }
                let latestAnalyzed = allRepos
                    .compactMap { formattedAnalysisDate($0.analyzedAt) }
                    .max()

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    summaryMetricCard(
                        title: english ? "Repositories" : "対象リポジトリ",
                        value: "\(allRepos.count)",
                        subtitle: english ? "Saved analyses" : "保存済み解析",
                        symbol: "folder.fill",
                        tint: SemanticColors.role("actionText")
                    )
                    summaryMetricCard(
                        title: english ? "Total Findings" : "総指摘件数",
                        value: "\(totalFindings)",
                        subtitle: english ? "Across all repos" : "全リポジトリ合計",
                        symbol: "exclamationmark.bubble.fill",
                        tint: SemanticColors.role("warningText")
                    )
                    summaryMetricCard(
                        title: english ? "Critical / High" : "重大・高リスク",
                        value: english ? "\(highRiskRepos.count) repos" : "\(highRiskRepos.count) リポジトリ",
                        subtitle: english
                            ? "Out of \(allRepos.count) total · \(highRiskFindings) findings"
                            : "全\(allRepos.count)件中 · 該当指摘 \(highRiskFindings)件",
                        symbol: "shield.lefthalf.filled.badge.checkmark",
                        tint: SemanticColors.role("dangerText")
                    )
                    summaryMetricCard(
                        title: english ? "Latest Analysis" : "最新解析",
                        value: latestAnalyzed ?? (english ? "Not yet" : "未記録"),
                        subtitle: english ? "Local scan time" : "ローカル解析日時",
                        symbol: "clock.fill",
                        tint: SemanticColors.role("infoText")
                    )
                }

                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text(english ? "Top Priority Repositories" : "優先対応リポジトリ（危険度順）")
                            .font(.headline)
                        Spacer()
                        Button {
                            showPage(.audit)
                        } label: {
                            Label(english ? "Open Audit List" : "監査結果一覧を見る", systemImage: "arrow.right.circle")
                        }
                    }
                    let topRisk = Array(sortDashboardRepositories(highRiskRepos, by: .severityDesc).prefix(5))
                    if allRepos.isEmpty {
                        ContentUnavailableView(
                            english ? "No saved analyses" : "保存済みの解析はありません",
                            systemImage: "folder.badge.plus",
                            description: Text(english ? "Add a GitHub URL to begin." : "GitHub URL を追加して始めましょう。")
                        )
                    } else if topRisk.isEmpty {
                        ContentUnavailableView(
                            english ? "No Critical or High risk repositories" : "重大・高リスクのリポジトリはありません",
                            systemImage: "checkmark.shield.fill",
                            description: Text(
                                english
                                    ? "All \(allRepos.count) analyzed repositories are medium/low risk or clean. Open the Audit List for details."
                                    : "全 \(allRepos.count) 件の解析済みリポジトリは中・低リスク以下またはクリーンです。詳細は「監査結果一覧を見る」から確認できます。"
                            )
                        )
                    } else {
                        VStack(spacing: 0) {
                            ForEach(topRisk) { repo in
                                repositoryRow(repo)
                                if repo.id != topRisk.last?.id { Divider().padding(.leading, 48) }
                            }
                        }
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator.opacity(0.5)))
                    }
                }
            }
            .padding(32)
            .frame(maxWidth: 1100, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    @ViewBuilder
    private func summaryMetricCard(title: String, value: String, subtitle: String, symbol: String, tint: Color) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(title)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Image(systemName: symbol)
                        .foregroundStyle(tint)
                }
                Text(value)
                    .font(.title3.bold().monospacedDigit())
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var auditListView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 10) {
                        Text(english ? "Saved analyses" : "保存済みの解析").font(.headline)
                        Text("\(dashboardRepositories.count)").foregroundStyle(.secondary)
                        Spacer()
                        if !listRefreshNote.isEmpty {
                            Text(listRefreshNote)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Picker(english ? "Sort" : "並び替え", selection: $dashboardSortOrderRaw) {
                            ForEach(DashboardSortOrder.allCases) { option in
                                Text(option.title(english: english)).tag(option.rawValue)
                            }
                        }
                        .labelsHidden()
                        .frame(width: 195)
                        .help(english ? "Sort saved analyses" : "保存済みの解析を並び替え")
                        Button {
                            Task { await reloadAndAnalyzeRepositories() }
                        } label: {
                            HStack(spacing: 6) {
                                if refreshingList {
                                    ProgressView()
                                        .controlSize(.small)
                                } else {
                                    Image(systemName: "arrow.clockwise")
                                }
                                Text(refreshingList
                                     ? (english ? "Analyzing…" : "解析中…")
                                     : (english ? "Reload list" : "一覧を更新"))
                            }
                        }
                        .disabled(refreshingList || !coordinator.ready)
                    }
                    if dashboardRepositories.isEmpty {
                        ContentUnavailableView(
                            query.isEmpty ? (english ? "No timestamped analyses yet" : "解析日時付きの保存データはありません") :
                                (english ? "No matching repositories" : "一致するリポジトリはありません"),
                            systemImage: query.isEmpty ? "folder.badge.plus" : "magnifyingglass",
                            description: Text(query.isEmpty ?
                                (english ? "Click \"Reload list\" or re-scan a repository to record an analysis timestamp." : "「一覧を更新」またはリポジトリの再スキャンを実行すると解析日時が記録されてここに表示されます。") :
                                (english ? "Try another search." : "検索語を変更してください。")))
                    } else {
                        let visibleRepos = pagedDashboardRepositories
                        VStack(spacing: 0) {
                            ForEach(visibleRepos) { repo in
                                repositoryRow(repo)
                                if repo.id != visibleRepos.last?.id { Divider().padding(.leading, 48) }
                            }
                        }
                        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator.opacity(0.5)))

                        HStack(spacing: 12) {
                            HStack(spacing: 6) {
                                Text(english ? "Per page" : "表示件数")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Picker(english ? "Per page" : "表示件数", selection: $dashboardPageSize) {
                                    ForEach([10, 20, 30, 40, 50], id: \.self) { size in
                                        Text(english ? "\(size)" : "\(size)件").tag(size)
                                    }
                                }
                                .labelsHidden()
                                .frame(width: 78)
                            }
                            Spacer()
                            let currentPage = min(dashboardPageIndex, max(0, dashboardPageCount - 1)) + 1
                            Text(english
                                 ? "Page \(currentPage) of \(dashboardPageCount) (\(dashboardRepositories.count) items)"
                                 : "\(currentPage) / \(dashboardPageCount) ページ（全 \(dashboardRepositories.count) 件）")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            HStack(spacing: 6) {
                                Button {
                                    dashboardPageIndex = max(0, min(dashboardPageIndex, dashboardPageCount - 1) - 1)
                                } label: {
                                    Label(english ? "Previous" : "前へ", systemImage: "chevron.left")
                                }
                                .disabled(currentPage <= 1)
                                Button {
                                    dashboardPageIndex = min(dashboardPageCount - 1, currentPage)
                                } label: {
                                    Label(english ? "Next" : "次へ", systemImage: "chevron.right")
                                }
                                .disabled(currentPage >= dashboardPageCount)
                            }
                        }
                        .padding(.top, 4)
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
            selection = ["repo:" + repo.id]
            coordinator.page = .audit
            coordinator.send("repository", value: repo.id)
            coordinator.send("page", value: WorkspacePage.audit.command)
        } label: {
            HStack(spacing: 14) {
                Image(systemName: "folder").font(.title3).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 5) {
                    Text(repo.name).font(.body.weight(.medium)).lineLimit(1)
                    HStack(spacing: 6) {
                        Text(repo.commit.isEmpty ? (english ? "Commit not recorded" : "コミット未記録") : String(repo.commit.prefix(10)))
                        Text("·")
                        if let analyzedLabel = formattedAnalysisDate(repo.analyzedAt) {
                            Text(english ? "Analyzed: \(analyzedLabel)" : "解析日時: \(analyzedLabel)")
                        } else if let ghUpdated = formattedAnalysisDate(repo.updatedAt) {
                            Text(english ? "Analysis date not recorded (GitHub updated: \(ghUpdated))" : "解析日時未記録 (GitHub更新: \(ghUpdated))")
                        } else {
                            Text(english ? "Analysis date not recorded" : "解析日時未記録")
                        }
                    }
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
        .contextMenu {
            repositoryContextMenu(for: repo)
        }
    }

    private var selectedRepositories: [WorkspaceRepository] {
        let selectedIDs = Set(selection.filter { $0.hasPrefix("repo:") }.map { String($0.dropFirst(5)) })
        return repositories.filter { selectedIDs.contains($0.id) }
    }

    private func targetRepositories(for clicked: WorkspaceRepository) -> [WorkspaceRepository] {
        let selected = selectedRepositories
        if selected.count > 1 && selected.contains(where: { $0.id == clicked.id }) {
            return selected
        }
        return [clicked]
    }

    @ViewBuilder
    private func repositoryContextMenu(for repo: WorkspaceRepository) -> some View {
        let targets = targetRepositories(for: repo)
        let updatable = targets.filter { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

        if targets.count == 1 {
            Button {
                selection = ["repo:" + repo.id]
                coordinator.page = .chat
                coordinator.send("copilot-chat", value: repo.id)
            } label: {
                Label(english ? "Ask AI / Copilot" : "AI / Copilot に相談", systemImage: "bubble.left.and.bubble.right")
            }
        }

        Button {
            Task { await runRepositoryBatch(updatable, endpoint: "/api/analyze") }
        } label: {
            Label(
                targets.count > 1
                    ? (english ? "Re-scan \(targets.count) Selected Repositories" : "選択した \(targets.count) 件を再スキャン")
                    : (english ? "Re-scan Repository" : "再スキャン"),
                systemImage: "arrow.trianglehead.2.clockwise.rotate.90"
            )
        }
        .disabled(updatable.isEmpty || !busyRepoIDs.isEmpty)

        Button {
            Task { await runRepositoryBatch(updatable, endpoint: "/api/sync") }
        } label: {
            Label(
                targets.count > 1
                    ? (english ? "Update \(targets.count) Selected Repositories" : "選択した \(targets.count) 件を更新")
                    : (english ? "Update Repository" : "リポジトリを更新"),
                systemImage: "arrow.clockwise"
            )
        }
        .disabled(updatable.isEmpty || !busyRepoIDs.isEmpty)

        if targets.count == 1,
           let url = URL(string: repo.url.trimmingCharacters(in: .whitespacesAndNewlines)),
           url.scheme == "https" {
            Button {
                NSWorkspace.shared.open(url)
            } label: {
                Label(english ? "Open on GitHub" : "GitHub で開く", systemImage: "safari")
            }
        }

        Divider()

        Button(role: .destructive) {
            reposPendingDeletion = targets
        } label: {
            Label(
                targets.count > 1
                    ? (english ? "Remove \(targets.count) Selected from RepoAUDT" : "選択した \(targets.count) 件を RepoAUDT から削除")
                    : (english ? "Remove from RepoAUDT" : "RepoAUDT から削除"),
                systemImage: "trash"
            )
        }
        .disabled(!busyRepoIDs.isEmpty)
    }

    private func runRepositoryBatch(_ targets: [WorkspaceRepository], endpoint: String) async {
        let validTargets = targets.filter { !$0.url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        guard !validTargets.isEmpty, busyRepoIDs.isEmpty else { return }
        busyRepoIDs = Set(validTargets.map(\.id))
        defer { busyRepoIDs = [] }
        do {
            for target in validTargets {
                let targetURL = target.url.trimmingCharacters(in: .whitespacesAndNewlines)
                try await postRepositoryAction(endpoint, body: ["url": targetURL])
            }
            coordinator.send("refresh")
        } catch {
            repoActionError = error.localizedDescription
        }
    }

    private func deleteRepositories(_ targets: [WorkspaceRepository]) async {
        guard !targets.isEmpty, busyRepoIDs.isEmpty else { return }
        let targetIDs = targets.map(\.id)
        busyRepoIDs = Set(targetIDs)
        defer { busyRepoIDs = [] }
        do {
            if targetIDs.count == 1, let singleID = targetIDs.first {
                try await postRepositoryAction("/api/delete", body: ["id": singleID])
            } else {
                try await postRepositoryAction("/api/delete", body: ["ids": targetIDs])
            }
            let deletedTags = Set(targetIDs.map { "repo:" + $0 })
            selection.subtract(deletedTags)
            if selection.isEmpty {
                selection = [WorkspacePage.dashboard.rawValue]
                coordinator.page = .dashboard
            }
            coordinator.send("refresh")
        } catch {
            repoActionError = error.localizedDescription
        }
    }

    private func refreshGithubHealthStatus() async {
        guard backend.isReady, !checkingGithubHealth else { return }
        checkingGithubHealth = true
        defer { checkingGithubHealth = false }
        do {
            let json = try await requestJSON("/api/health")
            let services = json["services"] as? [[String: Any]] ?? []
            let apiSvc = services.first { ($0["id"] as? String) == "github_api" }
            let cliSvc = services.first { ($0["id"] as? String) == "gh_cli" }

            let apiStatus = (apiSvc?["status"] as? String ?? "ONLINE").uppercased()
            let apiDetails = apiSvc?["details"] as? String ?? ""
            let cliStatus = (cliSvc?["status"] as? String ?? "ONLINE").uppercased()
            let credStatus = cliSvc?["credential_status"] as? String ?? ""

            if apiStatus != "ONLINE" {
                githubConnectionIssue = english
                    ? "Cannot connect to GitHub (\(apiStatus))"
                    : "GitHub に接続できません（\(apiStatus)）"
                githubConnectionGuide = english
                    ? "Check your internet connection, VPN, or proxy settings. Detail: \(apiDetails)"
                    : "インターネット接続・VPN・プロキシ設定を確認してください。また、ターミナルで `gh auth login` を実行するか「AI 接続」画面で GitHub トークンを設定できます。（詳細: \(apiDetails)）"
            } else if cliStatus != "ONLINE" {
                githubConnectionIssue = english
                    ? "GitHub CLI (gh) is not connected"
                    : "GitHub CLI (gh) が GitHub に接続できていません"
                if credStatus == "not_installed" {
                    githubConnectionGuide = english
                        ? "Install GitHub CLI and sign in via Terminal: `brew install gh && gh auth login`, or configure a GitHub Token in AI Connections."
                        : "ターミナルで `brew install gh && gh auth login` を実行してサインインするか、「AI 接続」画面で GitHub トークンを設定してください。"
                } else {
                    githubConnectionGuide = english
                        ? "Run `gh auth login` in Terminal to connect your GitHub account, or set a GitHub Token in AI Connections."
                        : "ターミナルで `gh auth login` を実行して GitHub アカウントに接続するか、「AI 接続」画面で GitHub トークンを設定してください。"
                }
            } else {
                githubConnectionIssue = nil
                githubConnectionGuide = nil
            }
        } catch {
            // Keep silent if backend health is still warming up.
        }
    }

    private func refreshDashboardVersionHeader() async {
        guard backend.isReady else { return }
        do {
            let json = try await requestJSON("/api/app/update/check")
            if let commit = json["local_commit"] as? String, !commit.isEmpty {
                headerCommit = commit
            }
            let fmt = DateFormatter()
            fmt.dateFormat = "yyyy/MM/dd HH:mm"
            lastUpdateCheckLabel = fmt.string(from: Date())
        } catch {
            // Keep silent in background header check.
        }
    }

    private func reloadAndAnalyzeRepositories() async {
        guard !refreshingList else { return }
        refreshingList = true
        listRefreshNote = english ? "Starting analysis…" : "解析を開始しています…"
        defer { refreshingList = false }

        do {
            let syncResp = try await requestJSON("/api/sync", body: [:])
            let jobId = syncResp["job_id"] as? String ?? ""
            if !jobId.isEmpty {
                listRefreshNote = english ? "Analyzing repositories…" : "全リポジトリを解析中…"
                for attempt in 0..<180 {
                    try? await Task.sleep(for: .seconds(1))
                    let statusResp = try? await requestJSON("/api/sync/status?job_id=\(jobId)")
                    let status = statusResp?["status"] as? String ?? ""
                    if attempt % 3 == 2 {
                        coordinator.send("refresh")
                    }
                    if status == "completed" {
                        break
                    }
                }
            }
            await withCheckedContinuation { continuation in
                coordinator.send("refresh") {
                    continuation.resume()
                }
            }
            let formatter = DateFormatter()
            formatter.dateFormat = "HH:mm:ss"
            let time = formatter.string(from: Date())
            listRefreshNote = english
                ? "Analyzed \(time) · \(dashboardRepositories.count) items"
                : "解析完了 \(time) · \(dashboardRepositories.count)件"
            AppNotificationManager.sendAnalysisCompleted(
                title: english ? "Analysis Complete" : "RepoAUDT Mac 解析完了",
                body: english
                    ? "Finished analyzing \(dashboardRepositories.count) repositories."
                    : "\(dashboardRepositories.count)件のリポジトリの解析が完了しました。"
            )
        } catch {
            listRefreshNote = error.localizedDescription
        }
    }

    private func postRepositoryAction(_ path: String, body: [String: Any]) async throws {
        _ = try await requestJSON(path, body: body)
    }

    private func checkForAppUpdates() async {
        guard !checkingAppUpdate && !applyingAppUpdate else { return }
        checkingAppUpdate = true
        defer { checkingAppUpdate = false }
        do {
            let json = try await requestJSON("/api/app/update/check")
            let available = json["update_available"] as? Bool ?? false
            let localCommit = json["local_commit"] as? String ?? ""
            let remoteCommit = json["remote_commit"] as? String ?? ""
            let behindCount = json["behind_count"] as? Int ?? 0
            let latestMessage = json["latest_message"] as? String ?? ""
            let dirty = json["dirty"] as? Bool ?? false

            if available {
                appUpdatePrompt = AppUpdateInfo(
                    localCommit: localCommit,
                    remoteCommit: remoteCommit,
                    behindCount: behindCount,
                    latestMessage: latestMessage,
                    dirty: dirty
                )
            } else {
                appUpdateStatusMessage = english
                    ? "RepoAUDT Mac is up to date (\(localCommit))."
                    : "RepoAUDT Mac は最新です (\(localCommit))。"
            }
        } catch {
            appUpdateStatusMessage = error.localizedDescription
        }
    }

    private func applyAppUpdate() async {
        guard !applyingAppUpdate else { return }
        applyingAppUpdate = true
        defer { applyingAppUpdate = false }
        do {
            let json = try await requestJSON("/api/app/update/apply", body: [:])
            if json["already_latest"] as? Bool == true {
                let commit = json["local_commit"] as? String ?? ""
                appUpdateStatusMessage = english
                    ? "RepoAUDT Mac is already up to date (\(commit))."
                    : "RepoAUDT Mac はすでに最新です (\(commit))。"
            } else {
                appUpdateStatusMessage = english
                    ? "Updating and rebuilding RepoAUDT Mac… It will relaunch automatically when finished."
                    : "アップデートと再ビルドを開始しました。完了後に自動で再起動します。"
            }
        } catch {
            appUpdateStatusMessage = error.localizedDescription
        }
    }

    @discardableResult
    private func requestJSON(_ path: String, body: [String: Any]? = nil) async throws -> [String: Any] {
        guard let url = URL(string: "http://127.0.0.1:\(backend.port)\(path)") else {
            throw URLError(.badURL)
        }
        var request = URLRequest(url: url)
        request.timeoutInterval = 180
        if let body {
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NSError(domain: "RepoAUDT", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: english ? "Invalid response from local engine." : "ローカルエンジンから無効な応答が返されました。"])
        }
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? 0
        if statusCode != 200 || (json["ok"] as? Bool) == false {
            let msg = (json["error"] as? String)
                ?? (json["message"] as? String)
                ?? (english ? "Request failed (HTTP \(statusCode))." : "リクエストに失敗しました (HTTP \(statusCode))。")
            throw NSError(domain: "RepoAUDT", code: 2, userInfo: [NSLocalizedDescriptionKey: msg])
        }
        return json
    }
}
