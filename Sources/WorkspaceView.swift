import AppKit
import SwiftUI
import WebKit

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
    @State private var syncProgress: SyncProgressInfo?
    @State private var lastCompletedSyncAt: String?
    @State private var didInitializeLaunchPage = false
    @State private var triggerSidebarAppUpdate = false
    @State private var headerCommit = ""
    @State private var lastUpdateCheckLabel = ""
    @State private var githubConnectionIssue: String?
    @State private var githubConnectionGuide: String?
    @State private var checkingGithubHealth = false
    @State private var copyingHighRiskReport = false
    @State private var highRiskCopyStatus: String?
    @State private var monitorEnabled = true
    @State private var monitorIntervalSec = 900
    @State private var aspmRepos: [AspmRepoItem] = []
    @State private var aspmHistory: [AspmHistoryPoint] = []
    @State private var drilldownFilter: DashboardDrilldownFilter?
    @State private var drilldownItems: [DrilldownFindingItem] = []
    @State private var loadingDrilldown = false
    @State private var drilldownGrouped = true
    @State private var expandedDrilldownGroups: Set<String> = []
    @State private var drilldownCopyNotice: String?
    @State private var showRiskTrendReasons = false
    @State private var showAspmLegend = false
    @AppStorage("dashboardSectionOrder") private var dashboardSectionOrderRaw = "commit_monitor,monitor_updates,kpi,risk_trend,priority_repos,aspm,audit_scope"
    @AppStorage("dashboardCollapsedSections") private var dashboardCollapsedSectionsRaw = ""
    @State private var monitorChecking = false
    @State private var monitorLastCheckTime = ""
    @State private var monitorSummary = ""
    @State private var monitorLaunchdInstalled = false
    @State private var seenMonitorUpdateKeys: Set<String> = []
    @State private var monitorUpdates: [MonitorUpdateEvent] = []
    @State private var revocationChecks: [SecretRevocationItem] = []

    private struct ResolvedFindingSummary: Identifiable {
        let id = UUID()
        let title: String
        let file: String
        let severity: String
        let requiresRevoke: Bool
    }

    private struct SecretRevocationItem: Identifiable {
        let id: String
        let repo: String
        let title: String
        let file: String
        let severity: String
        let newCommit: String
        let resolvedAt: String
        let revokedConfirmed: Bool
        let confirmedAt: String?
    }

    private struct MonitorUpdateEvent: Identifiable {
        let id: String
        let repo: String
        let oldCommit: String
        let newCommit: String
        let findings: Int
        let resolvedCount: Int
        let resolvedHighCount: Int
        let newCount: Int
        let detectedAt: String
        let resolvedFindings: [ResolvedFindingSummary]
    }

    private struct SyncProgressInfo {
        let status: String
        let total: Int
        let completed: Int
        let currentRepo: String
        let currentStage: String
        let etaSeconds: Int?
        let logs: [String]
    }

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
                                Spacer(minLength: 4)
                                if busyRepoIDs.contains(repo.id) {
                                    ProgressView()
                                        .controlSize(.small)
                                } else if let aspm = aspmRepos.first(where: { $0.id == repo.id || $0.repo == repo.name }),
                                          (aspm.p0 + aspm.p1 + aspm.p2 + aspm.p3) > 0 {
                                    HStack(spacing: 3) {
                                        if aspm.p0 > 0 {
                                            sidebarTierPill(count: aspm.p0, color: Color(red: 0.88, green: 0.16, blue: 0.22), solid: true) {
                                                openDrilldown(tier: "P0", diagramId: repo.id, title: "\(repo.name) — P0")
                                            }
                                        }
                                        if aspm.p1 > 0 {
                                            sidebarTierPill(count: aspm.p1, color: .orange) {
                                                openDrilldown(tier: "P1", diagramId: repo.id, title: "\(repo.name) — P1")
                                            }
                                        }
                                        if aspm.p2 > 0 {
                                            sidebarTierPill(count: aspm.p2, color: .yellow) {
                                                openDrilldown(tier: "P2", diagramId: repo.id, title: "\(repo.name) — P2")
                                            }
                                        }
                                        if aspm.p3 > 0 {
                                            sidebarTierPill(count: aspm.p3, color: SemanticColors.role("infoText")) {
                                                openDrilldown(tier: "P3", diagramId: repo.id, title: "\(repo.name) — P3")
                                            }
                                        }
                                    }
                                } else if repo.findings > 0 {
                                    let sevColor = SemanticColors.severityColor(repo.severity)
                                    Text("\(repo.findings)")
                                        .font(.caption2.monospacedDigit().weight(.semibold))
                                        .foregroundStyle(sevColor)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(sevColor.opacity(0.18), in: Capsule())
                                }
                            }
                            .help({
                                if let aspm = aspmRepos.first(where: { $0.id == repo.id || $0.repo == repo.name }),
                                   (aspm.p0 + aspm.p1 + aspm.p2 + aspm.p3) > 0 {
                                    return "\(repo.name) — P0: \(aspm.p0) / P1: \(aspm.p1) / P2: \(aspm.p2) / P3: \(aspm.p3)"
                                }
                                return repo.findings > 0
                                    ? (english ? "\(repo.name) — \(repo.findings) findings (\(repo.severity))" : "\(repo.name) — 指摘 \(repo.findings)件（\(repo.severity)）")
                                    : repo.name
                            }())
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
                if page != .dashboard {
                    ToolbarItem(placement: .navigation) {
                        Button {
                            showPage(.dashboard)
                        } label: {
                            Label(english ? "Dashboard" : "ダッシュボードへ戻る", systemImage: "chevron.left")
                        }
                        .help(english ? "Back to Dashboard" : "ダッシュボードへ戻る")
                    }
                }
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
        .onReceive(NotificationCenter.default.publisher(for: .repoAudtExportPdf)) { notif in
            let targetRepo = notif.userInfo?["repo"] as? String ?? ""
            Task { await exportAuditPdfReport(repo: targetRepo) }
        }
        .onAppear {
            coordinator.language = language
            if !didInitializeLaunchPage {
                didInitializeLaunchPage = true
                coordinator.page = .dashboard
                selection = [WorkspacePage.dashboard.rawValue]
            }
            Task { await refreshAspmPortfolio() }
        }
        .sheet(item: $drilldownFilter) { filter in
            let groups = groupedDrilldownItems(drilldownItems)
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    Text(filter.title)
                        .font(.title3.bold())
                    Spacer()
                    if !drilldownItems.isEmpty {
                        Picker("", selection: $drilldownGrouped) {
                            Text(english ? "Grouped (\(groups.count))" : "グループ (\(groups.count))").tag(true)
                            Text(english ? "List" : "一覧").tag(false)
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 210)

                        Button {
                            copyDrilldownFixPrompt(for: groups)
                        } label: {
                            Label(
                                english ? "Copy All Fix Requests" : "すべて修正依頼コピー",
                                systemImage: "doc.on.doc"
                            )
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    Text(english ? "\(drilldownItems.count) items" : "\(drilldownItems.count) 件")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Button(english ? "Close" : "閉じる") {
                        drilldownFilter = nil
                    }
                    .keyboardShortcut(.cancelAction)
                }
                if let notice = drilldownCopyNotice {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.circle.fill")
                        Text(notice)
                    }
                    .font(.caption.weight(.medium))
                    .foregroundStyle(SemanticColors.role("successText"))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(SemanticColors.role("successText").opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
                }
                Divider()
                if loadingDrilldown {
                    ProgressView(english ? "Loading findings..." : "指摘を読み込み中…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if drilldownItems.isEmpty {
                    ContentUnavailableView(
                        english ? "No matching findings" : "該当する指摘はありません",
                        systemImage: "checkmark.shield"
                    )
                } else if drilldownGrouped {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            ForEach(groups) { group in
                                let isExpanded = expandedDrilldownGroups.contains(group.id)
                                VStack(alignment: .leading, spacing: 0) {
                                    HStack(spacing: 10) {
                                        Button {
                                            if isExpanded {
                                                expandedDrilldownGroups.remove(group.id)
                                            } else {
                                                expandedDrilldownGroups.insert(group.id)
                                            }
                                        } label: {
                                            HStack(spacing: 8) {
                                                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                                                    .font(.caption.weight(.semibold))
                                                    .foregroundStyle(.secondary)
                                                    .frame(width: 12)
                                                Text(group.tier)
                                                    .font(.caption2.bold())
                                                    .padding(.horizontal, 6)
                                                    .padding(.vertical, 2)
                                                    .background(group.tierColor.opacity(0.18), in: Capsule())
                                                    .foregroundStyle(group.tierColor)
                                                Text(group.title)
                                                    .font(.subheadline.weight(.semibold))
                                                    .lineLimit(2)
                                                    .multilineTextAlignment(.leading)
                                            }
                                        }
                                        .buttonStyle(.plain)
                                        Spacer()
                                        Text(
                                            english
                                                ? "\(group.items.count) items · \(group.repoCount) repos"
                                                : "\(group.items.count)件 · \(group.repoCount)リポジトリ"
                                        )
                                        .font(.caption.monospacedDigit())
                                        .foregroundStyle(.secondary)
                                        Button {
                                            copyDrilldownFixPrompt(for: [group])
                                        } label: {
                                            Label(
                                                english ? "Copy Fix Request" : "一括修正依頼をコピー",
                                                systemImage: "doc.on.doc"
                                            )
                                        }
                                        .buttonStyle(.borderedProminent)
                                        .controlSize(.small)
                                    }
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 10)
                                    .background(Color(nsColor: .controlBackgroundColor))

                                    if isExpanded {
                                        Divider()
                                        VStack(alignment: .leading, spacing: 0) {
                                            ForEach(group.items) { item in
                                                HStack(alignment: .top, spacing: 10) {
                                                    VStack(alignment: .leading, spacing: 3) {
                                                        Text(item.repoName)
                                                            .font(.caption.weight(.semibold))
                                                        Text(item.file.isEmpty ? item.title : item.file)
                                                            .font(.caption.monospaced())
                                                            .foregroundStyle(.secondary)
                                                            .lineLimit(1)
                                                        if !item.reason.isEmpty {
                                                            Text(item.reason)
                                                                .font(.caption2)
                                                                .foregroundStyle(.tertiary)
                                                                .lineLimit(1)
                                                        }
                                                    }
                                                    Spacer()
                                                    Button(english ? "Open" : "開く") {
                                                        openDrilldownFinding(item)
                                                    }
                                                    .buttonStyle(.bordered)
                                                    .controlSize(.small)
                                                }
                                                .padding(.horizontal, 14)
                                                .padding(.vertical, 8)
                                                if item.id != group.items.last?.id {
                                                    Divider().padding(.leading, 14)
                                                }
                                            }
                                        }
                                        .background(Color(nsColor: .windowBackgroundColor).opacity(0.45))
                                    }
                                }
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.45)))
                            }
                        }
                        .padding(.vertical, 2)
                    }
                } else {
                    List(drilldownItems) { item in
                        HStack(alignment: .top, spacing: 10) {
                            Text(item.tier)
                                .font(.caption2.bold())
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(item.tierColor.opacity(0.18), in: Capsule())
                                .foregroundStyle(item.tierColor)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title)
                                    .font(.subheadline.weight(.semibold))
                                    .lineLimit(2)
                                Text("\(item.repoName) · \(item.file)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                if !item.reason.isEmpty {
                                    Text(item.reason)
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                }
                            }
                            Spacer()
                            Button(english ? "Open" : "開く") {
                                openDrilldownFinding(item)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .padding(20)
            .frame(minWidth: 740, minHeight: 500)
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
        let allRepos = coordinator.repositories
        return ScrollView {
            VStack(alignment: .leading, spacing: 16) {
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
                    Button {
                        Task { await reloadAndAnalyzeRepositories() }
                    } label: {
                        if refreshingList {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.small)
                                Text(english ? "Analyzing…" : "解析中…")
                            }
                        } else {
                            Label(english ? "Analyze All" : "全リポジトリを解析", systemImage: "play.fill")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(refreshingList || !backend.isReady || allRepos.isEmpty)
                    .help(english ? "Start analyzing all saved repositories" : "保存済みの全リポジトリの解析を開始")
                    Button {
                        showPage(.audit)
                        coordinator.send("analyze")
                    } label: {
                        Label(english ? "Add Repository" : "リポジトリを追加", systemImage: "plus")
                    }
                    .buttonStyle(.bordered)
                    .disabled(!coordinator.ready)
                    .help(english ? "Analyze a GitHub URL" : "GitHub URL を指定して解析")
                    Divider()
                        .frame(height: 18)
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
                    await fetchMonitorStatus()
                }
                .task(id: backend.isReady) {
                    guard backend.isReady else { return }
                    await refreshAspmPortfolio()
                    while !Task.isCancelled {
                        await fetchMonitorStatus()
                        await refreshAspmPortfolio()
                        try? await Task.sleep(for: .seconds(15))
                    }
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
                if let progress = syncProgress {
                    liveSyncProgressCard(progress)
                }

                let p0Total = aspmRepos.reduce(0) { $0 + $1.p0 }
                let p1Total = aspmRepos.reduce(0) { $0 + $1.p1 }
                let p2Total = aspmRepos.reduce(0) { $0 + $1.p2 }
                let p3Total = aspmRepos.reduce(0) { $0 + $1.p3 }
                let totalFindings = aspmRepos.isEmpty
                    ? allRepos.reduce(0) { $0 + $1.findings }
                    : (p0Total + p1Total + p2Total + p3Total)
                let highRiskRepos = allRepos.filter { severityRank($0.severity) >= 4 }
                let highRiskFindings = highRiskRepos.reduce(0) { $0 + $1.findings }
                let repoLatestAnalyzed = allRepos.compactMap { formattedAnalysisDate($0.analyzedAt) }
                let syncLatestAnalyzed = formattedAnalysisDate(lastCompletedSyncAt)
                let latestAnalyzed = (repoLatestAnalyzed + (syncLatestAnalyzed.map { [$0] } ?? [])).max()
                let topRisk = Array(sortDashboardRepositories(highRiskRepos, by: .severityDesc).prefix(5))

                ForEach(orderedDashboardSections, id: \.self) { sectionId in
                    switch sectionId {
                    case "commit_monitor":
                        if !allRepos.isEmpty {
                            dashboardSectionWrapper(id: "commit_monitor", title: english ? "New Commit Monitor" : "新着コミット監視") {
                                EmptyView()
                            } content: {
                                commitMonitorBar()
                            }
                        }

                    case "monitor_updates":
                        if !allRepos.isEmpty && (!revocationChecks.isEmpty || !monitorUpdates.isEmpty) {
                            dashboardSectionWrapper(id: "monitor_updates", title: english ? "New Commit Updates & Revocation" : "新着コミットで解消された監査結果・失効確認") {
                                EmptyView()
                            } content: {
                                VStack(alignment: .leading, spacing: 10) {
                                    if !revocationChecks.isEmpty {
                                        revocationChecklistCard()
                                    }
                                    if !monitorUpdates.isEmpty {
                                        monitorUpdatesCard()
                                    }
                                }
                            }
                        }

                    case "kpi":
                        dashboardSectionWrapper(id: "kpi", title: english ? "Security KPI & Priority Summary" : "セキュリティKPI・優先度サマリー") {
                            EmptyView()
                        } content: {
                            VStack(alignment: .leading, spacing: 12) {
                                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                                    summaryMetricCard(
                                        title: english ? "Repositories" : "対象リポジトリ",
                                        value: "\(allRepos.count)",
                                        subtitle: english ? "Saved analyses" : "保存済み解析",
                                        symbol: "folder.fill",
                                        tint: SemanticColors.role("actionText")
                                    ) {
                                        showPage(.audit)
                                    }
                                    summaryMetricCard(
                                        title: english ? "Total Findings" : "総指摘件数",
                                        value: "\(totalFindings)",
                                        subtitle: english ? "Across all repos" : "全リポジトリ合計",
                                        symbol: "exclamationmark.bubble.fill",
                                        tint: SemanticColors.role("warningText")
                                    ) {
                                        openDrilldown(tier: nil, title: english ? "All Findings" : "全リポジトリの指摘一覧")
                                    }
                                    summaryMetricCard(
                                        title: english ? "Critical / High" : "重大・高リスク",
                                        value: english ? "\(highRiskRepos.count) repos" : "\(highRiskRepos.count) リポジトリ",
                                        subtitle: english
                                            ? "Out of \(allRepos.count) total · \(highRiskFindings) findings"
                                            : "全\(allRepos.count)件中 · 該当指摘 \(highRiskFindings)件",
                                        symbol: "shield.lefthalf.filled.badge.checkmark",
                                        tint: SemanticColors.role("dangerText")
                                    ) {
                                        openDrilldown(tier: "HIGH_CRIT", title: english ? "Critical / High Findings (P0 / P1)" : "重大・高リスク指摘（P0 / P1）")
                                    }
                                    summaryMetricCard(
                                        title: english ? "Latest Analysis" : "最新解析",
                                        value: latestAnalyzed ?? (english ? "Not yet" : "未記録"),
                                        subtitle: english ? "Click to refresh" : "クリックで最新化",
                                        symbol: "clock.fill",
                                        tint: SemanticColors.role("infoText")
                                    ) {
                                        Task { await reloadAndAnalyzeRepositories() }
                                    }
                                }
                                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                                    summaryMetricCard(
                                        title: english ? "P0 Critical (Immediate)" : "P0 緊急対応",
                                        value: "\(p0Total)",
                                        subtitle: english ? "Secrets / Malware" : "シークレット漏洩 / マルウェア",
                                        symbol: "flame.fill",
                                        tint: p0Total > 0 ? SemanticColors.role("dangerText") : .secondary,
                                        highlightTint: p0Total > 0 ? SemanticColors.role("dangerText") : nil
                                    ) {
                                        openDrilldown(tier: "P0", title: english ? "P0 Critical Findings" : "P0 緊急対応一覧（シークレット・マルウェア）")
                                    }
                                    summaryMetricCard(
                                        title: english ? "P1 High (This Week)" : "P1 最優先",
                                        value: "\(p1Total)",
                                        subtitle: english ? "KEV / RCE / Auth Bypass" : "KEV / RCE / 認証バイパス",
                                        symbol: "exclamationmark.triangle.fill",
                                        tint: p1Total > 0 ? .orange : .secondary,
                                        highlightTint: p1Total > 0 ? .orange : nil
                                    ) {
                                        openDrilldown(tier: "P1", title: english ? "P1 High Findings" : "P1 最優先対応一覧（KEV / RCE 等）")
                                    }
                                    summaryMetricCard(
                                        title: english ? "P2 Planned" : "P2 計画対応",
                                        value: "\(p2Total)",
                                        subtitle: english ? "CI/CD / IaC / License" : "CI/CD / IaC / ライセンス",
                                        symbol: "wrench.and.screwdriver.fill",
                                        tint: p2Total > 0 ? .yellow : .secondary,
                                        highlightTint: p2Total > 0 ? .yellow : nil
                                    ) {
                                        openDrilldown(tier: "P2", title: english ? "P2 Planned Findings" : "P2 計画対応一覧")
                                    }
                                    summaryMetricCard(
                                        title: english ? "P3 Backlog" : "P3 低優先",
                                        value: "\(p3Total)",
                                        subtitle: english ? "Dev tools / Revoked" : "開発ツール / 失効済み等",
                                        symbol: "tray.full.fill",
                                        tint: p3Total > 0 ? SemanticColors.role("infoText") : .secondary,
                                        highlightTint: p3Total > 0 ? SemanticColors.role("infoText") : nil
                                    ) {
                                        openDrilldown(tier: "P3", title: english ? "P3 Backlog Findings" : "P3 低優先バックログ一覧")
                                    }
                                }
                            }
                        }

                    case "risk_trend":
                        if aspmHistory.filter({ $0.orgRiskScore != nil }).count >= 2 || !aspmRepos.isEmpty {
                            dashboardSectionWrapper(id: "risk_trend", title: english ? "Risk Score Trend (Org Average)" : "リスクスコア推移（全体平均トレンド）") {
                                EmptyView()
                            } content: {
                                riskTrendChartCard()
                            }
                        }

                    case "priority_repos":
                        dashboardSectionWrapper(id: "priority_repos", title: english ? "Top Priority Repositories" : "優先対応リポジトリ（危険度順）") {
                            HStack(spacing: 8) {
                                if let copyStatus = highRiskCopyStatus {
                                    Text(copyStatus)
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(SemanticColors.role("successText"))
                                }
                                if !highRiskRepos.isEmpty {
                                    Button {
                                        Task { await copyHighRiskReport() }
                                    } label: {
                                        if copyingHighRiskReport {
                                            HStack(spacing: 6) {
                                                ProgressView().controlSize(.small)
                                                Text(english ? "Preparing…" : "作成中…")
                                            }
                                        } else {
                                            Label(
                                                english ? "Copy High-Risk Report" : "重大・高リスクを一括コピー",
                                                systemImage: "doc.on.doc"
                                            )
                                        }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .controlSize(.small)
                                    .disabled(copyingHighRiskReport || !backend.isReady)

                                    Button {
                                        Task { await copySlackDigestReport() }
                                    } label: {
                                        Label(
                                            english ? "Slack Digest" : "Slack共有サマリー",
                                            systemImage: "text.bubble"
                                        )
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                    .disabled(copyingHighRiskReport || !backend.isReady)

                                    Button {
                                        Task { await exportAuditPdfReport() }
                                    } label: {
                                        Label(
                                            english ? "Export PDF" : "PDF報告書",
                                            systemImage: "doc.richtext"
                                        )
                                    }
                                    .buttonStyle(.bordered)
                                    .controlSize(.small)
                                    .disabled(copyingHighRiskReport || !backend.isReady)
                                }
                                Button {
                                    showPage(.audit)
                                } label: {
                                    Label(english ? "Open Audit List" : "監査結果一覧を見る", systemImage: "arrow.right.circle")
                                }
                                .controlSize(.small)
                            }
                        } content: {
                            if allRepos.isEmpty {
                                ContentUnavailableView(
                                    english ? "No saved analyses" : "保存済みの解析はありません",
                                    systemImage: "folder.badge.plus",
                                    description: Text(english ? "Add a GitHub URL to begin." : "GitHub URL を追加して始めましょう。")
                                )
                            } else if topRisk.isEmpty {
                                HStack(spacing: 12) {
                                    Image(systemName: "checkmark.shield.fill")
                                        .font(.title3)
                                        .foregroundStyle(SemanticColors.role("successText"))
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(english ? "No Critical or High risk repositories" : "重大・高リスクのリポジトリはありません")
                                            .font(.subheadline.weight(.semibold))
                                        Text(
                                            english
                                                ? "All \(allRepos.count) analyzed repositories are medium/low risk or clean. Open the Audit List for details."
                                                : "全 \(allRepos.count) 件の解析済みリポジトリは中・低リスク以下またはクリーンです。詳細は「監査結果一覧を見る」から確認できます。"
                                        )
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    }
                                    Spacer(minLength: 0)
                                }
                                .padding(.horizontal, 14)
                                .padding(.vertical, 10)
                                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
                                .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator.opacity(0.5)))
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

                    case "aspm":
                        if !aspmRepos.isEmpty {
                            dashboardSectionWrapper(id: "aspm", title: english ? "ASPM Portfolio & Coverage Matrix" : "ASPM 組織ポートフォリオ & 資産カバレッジ") {
                                HStack(spacing: 10) {
                                    Button {
                                        showAspmLegend.toggle()
                                    } label: {
                                        Label(english ? "Legend" : "見方", systemImage: "questionmark.circle")
                                    }
                                    .buttonStyle(.borderless)
                                    .font(.caption)
                                    .popover(isPresented: $showAspmLegend, arrowEdge: .top) {
                                        VStack(alignment: .leading, spacing: 8) {
                                            Text(english ? "ASPM Portfolio Guide" : "ASPM ポートフォリオの見方")
                                                .font(.headline)
                                            Text(english
                                                ? "• Gate: 🔴 BLOCK (unresolved P0 / Tier1 KEV) · 🟡 WARN (P1) · 🟢 PASS (clean)\n• Tier: Business criticality weight (Tier 1 Prod 1.5x / Tier 2 Internal 1.0x / Tier 3 Demo 0.5x)\n• Risk 0–100: Higher = riskier (P0–P3 × Tier × Public visibility)\n• Domains: Sec (Secrets) · SCA (Deps) · SAST (Code) · CI (Actions) · IaC (Infra) · GH (Repo Posture)\n• Status: ✅ Clean · ⚠️ Issues · ⬜ Unscanned (Blind Spot) · ➖ N/A"
                                                : "• ゲート: 🔴 BLOCK (P0/本番KEV残存) · 🟡 WARN (P1残存) · 🟢 PASS (安全)\n• Tier: 業務重要度重み (Tier 1 本番 1.5x / Tier 2 社内 1.0x / Tier 3 デモ 0.5x)\n• Risk 0–100: 高いほど危険 (P0〜P3 × Tier × 公開設定)\n• 6領域: Sec=鍵 · SCA=依存 · SAST=静的解析 · CI=Actions · IaC=構成 · GH=GitHub設定\n• 状態: ✅問題なし · ⚠️指摘あり · ⬜未検査 (Blind Spot) · ➖対象外")
                                                .font(.caption)
                                                .fixedSize(horizontal: false, vertical: true)
                                        }
                                        .padding(14)
                                        .frame(width: 440)
                                    }
                                    Button {
                                        Task { await refreshAspmPortfolio() }
                                    } label: {
                                        Label(english ? "Refresh" : "更新", systemImage: "arrow.clockwise")
                                    }
                                    .buttonStyle(.borderless)
                                    .font(.caption)
                                }
                            } content: {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text(
                                        english
                                            ? "🔴 BLOCK (P0) · 🟡 WARN (P1) · 🟢 PASS  |  Sec=Secrets · SCA=Deps · SAST=Code · CI=Actions · IaC=Infra · GH=Posture  |  ✅ Clean  ⚠️ Issues  ⬜ Unscanned  ➖ N/A"
                                            : "🔴 BLOCK (P0) · 🟡 WARN (P1) · 🟢 PASS  ｜  Sec=鍵 · SCA=依存 · SAST=静的 · CI=Actions · IaC=構成 · GH=設定  ｜  ✅安全  ⚠️指摘  ⬜未検査  ➖対象外"
                                    )
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 5)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color(nsColor: .controlBackgroundColor).opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
                                    VStack(spacing: 6) {
                                        ForEach(aspmRepos.prefix(8)) { item in
                                            Button {
                                                selection = ["repo:\(item.id)"]
                                            } label: {
                                                HStack(spacing: 10) {
                                                    Text(item.gateEmoji + " " + item.releaseGate)
                                                        .font(.caption.weight(.bold))
                                                        .padding(.horizontal, 6)
                                                        .padding(.vertical, 2)
                                                        .background(item.gateColor.opacity(0.15), in: Capsule())
                                                        .foregroundStyle(item.gateColor)
                                                    Text(item.repo)
                                                        .font(.subheadline.weight(.semibold))
                                                        .lineLimit(1)
                                                    Text(item.criticalityLabel(english: english))
                                                        .font(.caption2)
                                                        .foregroundStyle(.secondary)
                                                    Spacer()
                                                    Text("Risk \(item.riskScore)/100")
                                                        .font(.caption.monospacedDigit().weight(.semibold))
                                                        .foregroundStyle(riskScoreColor(item.riskScore))
                                                    Text(item.coverageCompact)
                                                        .font(.caption2.monospaced())
                                                        .foregroundStyle(.secondary)
                                                }
                                                .padding(.horizontal, 12)
                                                .padding(.vertical, 8)
                                                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
                                                .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.4)))
                                            }
                                            .buttonStyle(.plain)
                                            .help(item.gateReasons.joined(separator: " / "))
                                        }
                                    }
                                }
                            }
                        }

                    case "audit_scope":
                        dashboardSectionWrapper(id: "audit_scope", title: english ? "What RepoAUDT Audits" : "実施する監査内容") {
                            EmptyView()
                        } content: {
                            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                                auditScopeItem(
                                    title: english ? "Dependencies, Malware & OSS Licenses (OSV + Trivy)" : "依存関係・マルウェア・OSSライセンス（OSV + Trivy）",
                                    summary: english
                                        ? "Detects CVEs (KEV/EPSS), MAL-* malicious packages, EOL runtimes, AGPL/GPL licenses, and exports CycloneDX SBOMs."
                                        : "既知 CVE（KEV/EPSS）、MAL-* マルウェア、ランタイム EOL、AGPL/GPL ライセンスを検出し、CycloneDX SBOM を出力します。",
                                    symbol: "shippingbox.fill",
                                    tint: SemanticColors.role("dangerText")
                                )
                                auditScopeItem(
                                    title: english ? "Source SAST & IaC (Semgrep + Ruff + Trivy)" : "ソースコード・IaC 静的解析（Semgrep + Ruff + Trivy）",
                                    summary: english
                                        ? "Data-flow analysis for SQLi/XSS, Terraform/Dockerfile misconfigs, and structured Why/How/Verify AI fix proposals."
                                        : "SQLi/XSS 等のデータフロー解析、Terraform/Dockerfile 設定ミス検出、Why/How/Verify 構造化パッチ提案を行います。",
                                    symbol: "magnifyingglass.circle.fill",
                                    tint: SemanticColors.role("warningText")
                                )
                                auditScopeItem(
                                    title: english ? "Secrets & Opt-in Liveness Check (Gitleaks)" : "シークレット検出＆生存確認（Gitleaks + Opt-in Verify）",
                                    summary: english
                                        ? "Detects leaked API keys with masking and supports opt-in read-only Active/Revoked verification."
                                        : "API キーや認証トークンの誤コミットをマスク検出し、手動オプトインで読み取り専用の有効/失効確認が行えます。",
                                    symbol: "key.fill",
                                    tint: SemanticColors.role("actionText")
                                )
                                auditScopeItem(
                                    title: english ? "CI/CD, GitHub Posture & ASPM Gate (zizmor + ASPM)" : "GitHub Actions・Posture・ASPM ゲート（zizmor + ASPM）",
                                    summary: english
                                        ? "Audits workflow permissions/injections, repo visibility/branch protection, criticality Risk Score, and PASS/WARN/BLOCK gates."
                                        : "ワークフロー権限・インジェクション、リポジトリ保護設定、重要度加重 Risk Score と PASS/WARN/BLOCK ゲートを評価します。",
                                    symbol: "gearshape.2.fill",
                                    tint: SemanticColors.role("infoText")
                                )
                            }
                        }

                    default:
                        EmptyView()
                    }
                }
            }
            .padding(32)
            .frame(maxWidth: 1100, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    private var orderedDashboardSections: [String] {
        let defaults = ["commit_monitor", "monitor_updates", "kpi", "risk_trend", "priority_repos", "aspm", "audit_scope"]
        let parsed = dashboardSectionOrderRaw.split(separator: ",").map(String.init).filter { defaults.contains($0) }
        let missing = defaults.filter { !parsed.contains($0) }
        return parsed + missing
    }

    private func isDashboardSectionCollapsed(_ id: String) -> Bool {
        dashboardCollapsedSectionsRaw.split(separator: ",").map(String.init).contains(id)
    }

    private func toggleDashboardSection(_ id: String) {
        var set = Set(dashboardCollapsedSectionsRaw.split(separator: ",").map(String.init))
        if set.contains(id) {
            set.remove(id)
        } else {
            set.insert(id)
        }
        dashboardCollapsedSectionsRaw = set.sorted().joined(separator: ",")
    }

    private func moveDashboardSection(_ id: String, delta: Int) {
        var order = orderedDashboardSections
        guard let idx = order.firstIndex(of: id) else { return }
        let next = idx + delta
        guard next >= 0 && next < order.count else { return }
        order.swapAt(idx, next)
        dashboardSectionOrderRaw = order.joined(separator: ",")
    }

    @ViewBuilder
    private func dashboardSectionWrapper<Trailing: View, Content: View>(
        id: String,
        title: String,
        @ViewBuilder headerTrailing: () -> Trailing,
        @ViewBuilder content: () -> Content
    ) -> some View {
        let collapsed = isDashboardSectionCollapsed(id)
        let order = orderedDashboardSections
        let idx = order.firstIndex(of: id) ?? 0
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Button {
                    withAnimation(.easeInOut(duration: 0.15)) {
                        toggleDashboardSection(id)
                    }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: collapsed ? "chevron.right" : "chevron.down")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .frame(width: 12)
                        Text(title)
                            .font(.headline)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                Spacer(minLength: 8)

                headerTrailing()

                HStack(spacing: 2) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            moveDashboardSection(id, delta: -1)
                        }
                    } label: {
                        Image(systemName: "arrow.up")
                            .font(.caption2)
                    }
                    .buttonStyle(.borderless)
                    .disabled(idx == 0)
                    .help(english ? "Move section up" : "上へ移動")

                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            moveDashboardSection(id, delta: 1)
                        }
                    } label: {
                        Image(systemName: "arrow.down")
                            .font(.caption2)
                    }
                    .buttonStyle(.borderless)
                    .disabled(idx >= order.count - 1)
                    .help(english ? "Move section down" : "下へ移動")
                }
                .padding(.leading, 4)
            }

            if !collapsed {
                content()
            }
        }
    }

    @ViewBuilder
    private func auditScopeItem(title: String, summary: String, symbol: String, tint: Color) -> some View {
        GroupBox {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: symbol)
                    .font(.title3)
                    .foregroundStyle(tint)
                    .frame(width: 24)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                    Text(summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(10)
        }
    }

    private func sidebarTierPill(count: Int, color: Color, solid: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text("\(count)")
                .font(.caption2.monospacedDigit().weight(solid ? .bold : .semibold))
                .foregroundStyle(solid ? .white : color)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(solid ? color : color.opacity(0.18), in: Capsule())
        }
        .buttonStyle(.plain)
    }

    private func riskScoreColor(_ score: Int) -> Color {
        switch score {
        case 80...: return SemanticColors.role("dangerText")
        case 50..<80: return SemanticColors.role("warningText")
        case 20..<50: return SemanticColors.role("actionText")
        default: return SemanticColors.role("successText")
        }
    }

    @ViewBuilder
    private func riskTrendChartCard() -> some View {
        let orgHistory = aspmHistory.filter { $0.orgRiskScore != nil }
        let pts = Array(orgHistory.suffix(20))
        let liveOrgAvg = aspmRepos.isEmpty ? 0 : Int((Double(aspmRepos.reduce(0) { $0 + $1.riskScore }) / Double(aspmRepos.count)).rounded())
        let latest = pts.last
        let prev = pts.count >= 2 ? pts[pts.count - 2] : nil
        let latestScore = latest?.orgRiskScore ?? liveOrgAvg
        let latestColor = riskScoreColor(latestScore)
        let scoreDelta = prev.flatMap { p in latest?.orgRiskScore.map { $0 - (p.orgRiskScore ?? p.riskScore) } } ?? 0
        let avgScore = pts.isEmpty ? liveOrgAvg : pts.reduce(0) { $0 + ($1.orgRiskScore ?? $1.riskScore) } / pts.count
        let totalNew = pts.reduce(0) { $0 + $1.newCount }
        let totalResolved = pts.reduce(0) { $0 + $1.resolvedCount }
        let p0Total = aspmRepos.reduce(0) { $0 + $1.p0 }
        let p1Total = aspmRepos.reduce(0) { $0 + $1.p1 }

        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .center, spacing: 20) {
                    GeometryReader { geo in
                        let w = max(1, geo.size.width)
                        let h = max(1, geo.size.height)
                        let pad: CGFloat = 8
                        let usableW = max(1, w - pad * 2)
                        let usableH = max(1, h - pad * 2)

                        ZStack {
                            // Subtle horizontal reference lines (0, 50, 100)
                            ForEach([0.0, 0.5, 1.0], id: \.self) { frac in
                                let y = pad + usableH * CGFloat(1.0 - frac)
                                Path { p in
                                    p.move(to: CGPoint(x: pad, y: y))
                                    p.addLine(to: CGPoint(x: w - pad, y: y))
                                }
                                .stroke(Color.secondary.opacity(0.18), style: StrokeStyle(lineWidth: 1, dash: [3, 3]))
                            }

                            if pts.count < 2 {
                                Text(english ? "Collecting org-wide trend snapshots (chart appears after next scan)" : "全体平均トレンドを蓄積中（次回の解析から推移グラフが表示されます）")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .multilineTextAlignment(.center)
                                    .padding(.horizontal, 12)
                            } else {
                                // Area fill
                                Path { path in
                                    for (idx, pt) in pts.enumerated() {
                                        let x = pad + usableW * CGFloat(idx) / CGFloat(max(1, pts.count - 1))
                                        let norm = min(1.0, max(0.0, Double(pt.orgRiskScore ?? pt.riskScore) / 100.0))
                                        let y = pad + usableH * CGFloat(1.0 - norm)
                                        if idx == 0 {
                                            path.move(to: CGPoint(x: x, y: h - pad))
                                            path.addLine(to: CGPoint(x: x, y: y))
                                        } else {
                                            path.addLine(to: CGPoint(x: x, y: y))
                                        }
                                    }
                                    path.addLine(to: CGPoint(x: w - pad, y: h - pad))
                                    path.closeSubpath()
                                }
                                .fill(
                                    LinearGradient(
                                        colors: [latestColor.opacity(0.28), latestColor.opacity(0.02)],
                                        startPoint: .top,
                                        endPoint: .bottom
                                    )
                                )

                                // Line stroke
                                Path { path in
                                    for (idx, pt) in pts.enumerated() {
                                        let x = pad + usableW * CGFloat(idx) / CGFloat(max(1, pts.count - 1))
                                        let norm = min(1.0, max(0.0, Double(pt.orgRiskScore ?? pt.riskScore) / 100.0))
                                        let y = pad + usableH * CGFloat(1.0 - norm)
                                        if idx == 0 {
                                            path.move(to: CGPoint(x: x, y: y))
                                        } else {
                                            path.addLine(to: CGPoint(x: x, y: y))
                                        }
                                    }
                                }
                                .stroke(latestColor, style: StrokeStyle(lineWidth: 2.2, lineCap: .round, lineJoin: .round))
                            }
                        }
                    }
                    .frame(height: 84)
                    .background(Color(nsColor: .windowBackgroundColor).opacity(0.45), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.4)))

                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            Text(english ? "Latest:" : "直近スコア:")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text("\(latestScore) / 100")
                                .font(.subheadline.bold().monospacedDigit())
                                .foregroundStyle(latestColor)
                            if prev != nil && scoreDelta != 0 {
                                Text(scoreDelta > 0 ? "▲+\(scoreDelta)" : "▼\(scoreDelta)")
                                    .font(.caption2.bold().monospacedDigit())
                                    .foregroundStyle(scoreDelta > 0 ? SemanticColors.role("dangerText") : SemanticColors.role("successText"))
                            }
                            Text(english ? "(Avg \(avgScore))" : "(平均 \(avgScore))")
                                .font(.caption2.monospacedDigit().weight(.medium))
                                .foregroundStyle(riskScoreColor(avgScore))
                        }
                        Text("P0: \(p0Total) · P1: \(p1Total)")
                            .font(.caption.monospacedDigit().weight(.semibold))
                        Text(english ? "New: +\(totalNew) · Resolved: -\(totalResolved)" : "新規: +\(totalNew) · 解消: -\(totalResolved)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                        HStack(spacing: 8) {
                            Text(english ? "Last \(pts.count) scans" : "直近 \(pts.count) スキャン")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                            if !pts.isEmpty {
                                Button {
                                    withAnimation(.easeInOut(duration: 0.16)) {
                                        showRiskTrendReasons.toggle()
                                    }
                                } label: {
                                    HStack(spacing: 3) {
                                        Text(english ? (showRiskTrendReasons ? "Hide Reasons" : "Why it changed") : (showRiskTrendReasons ? "理由を閉じる" : "変動理由を見る"))
                                        Image(systemName: showRiskTrendReasons ? "chevron.up" : "chevron.down")
                                            .font(.caption2)
                                    }
                                    .font(.caption2.weight(.medium))
                                }
                                .buttonStyle(.link)
                            }
                        }
                    }
                    .frame(width: 230, alignment: .leading)
                }

                if showRiskTrendReasons && !pts.isEmpty {
                    Divider()
                    VStack(alignment: .leading, spacing: 6) {
                        Text(english ? "Recent Scan Score Changes (Newest First)" : "直近スキャンのスコア変動理由（新しい順）")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        ForEach(Array(pts.reversed().prefix(10))) { pt in
                            HStack(spacing: 10) {
                                Text(pt.shortTimestamp)
                                    .font(.caption2.monospacedDigit())
                                    .foregroundStyle(.tertiary)
                                    .frame(width: 76, alignment: .leading)
                                Text(pt.repo.isEmpty ? (english ? "Organization" : "全体") : pt.repo)
                                    .font(.caption.weight(.medium))
                                    .lineLimit(1)
                                    .frame(maxWidth: 210, alignment: .leading)
                                Text("Risk \(pt.repoRiskScore)")
                                    .font(.caption.monospacedDigit().weight(.semibold))
                                    .foregroundStyle(riskScoreColor(pt.repoRiskScore))
                                if pt.repoDelta != 0 {
                                    Text(pt.repoDelta > 0 ? "▲+\(pt.repoDelta)" : "▼\(pt.repoDelta)")
                                        .font(.caption2.bold().monospacedDigit())
                                        .foregroundStyle(pt.repoDelta > 0 ? SemanticColors.role("dangerText") : SemanticColors.role("successText"))
                                } else {
                                    Text(english ? "±0" : "±0")
                                        .font(.caption2.monospacedDigit())
                                        .foregroundStyle(.tertiary)
                                }
                                Spacer()
                                HStack(spacing: 6) {
                                    if pt.newCount > 0 {
                                        Text(english ? "+\(pt.newCount) new" : "新規+\(pt.newCount)")
                                            .font(.caption2.monospacedDigit())
                                            .foregroundStyle(SemanticColors.role("dangerText"))
                                    }
                                    if pt.resolvedCount > 0 {
                                        Text(english ? "-\(pt.resolvedCount) fixed" : "解消-\(pt.resolvedCount)")
                                            .font(.caption2.monospacedDigit())
                                            .foregroundStyle(SemanticColors.role("successText"))
                                    }
                                    Text("P0:\(pt.p0Count) P1:\(pt.p1Count)")
                                        .font(.caption2.monospacedDigit())
                                        .foregroundStyle(.secondary)
                                    if pt.orgRiskScore == nil {
                                        Text(english ? "(single repo)" : "(単体)")
                                            .font(.caption2)
                                            .foregroundStyle(.tertiary)
                                    }
                                }
                            }
                            .padding(.vertical, 2)
                        }
                    }
                    .padding(.top, 2)
                }
            }
            .padding(10)
        }
    }

    private func summaryMetricCard(
        title: String,
        value: String,
        subtitle: String,
        symbol: String,
        tint: Color,
        highlightTint: Color? = nil,
        action: (() -> Void)? = nil
    ) -> some View {
        let content = GroupBox {
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
                    .foregroundStyle(highlightTint ?? .primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
                HStack(spacing: 4) {
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if action != nil {
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .background(
            highlightTint.map { $0.opacity(0.12) } ?? Color.clear,
            in: RoundedRectangle(cornerRadius: 8)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(highlightTint?.opacity(0.42) ?? Color.clear, lineWidth: 1)
        )
        return Group {
            if let action {
                Button(action: action) {
                    content
                }
                .buttonStyle(.plain)
            } else {
                content
            }
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
                    HStack(spacing: 12) {
                        HStack(spacing: 4) {
                            Text("P0")
                                .font(.caption2.bold())
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(SemanticColors.role("dangerText").opacity(0.18), in: Capsule())
                                .foregroundStyle(SemanticColors.role("dangerText"))
                            Text(english ? "Critical (Secrets/Malware)" : "緊急（シークレット漏洩等）")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 4) {
                            Text("P1")
                                .font(.caption2.bold())
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(SemanticColors.role("warningText").opacity(0.18), in: Capsule())
                                .foregroundStyle(SemanticColors.role("warningText"))
                            Text(english ? "High (Immediate Fix)" : "高（重大脆弱性・即時対応）")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 4) {
                            Text("P2")
                                .font(.caption2.bold())
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(SemanticColors.role("actionText").opacity(0.18), in: Capsule())
                                .foregroundStyle(SemanticColors.role("actionText"))
                            Text(english ? "Medium (Planned Fix)" : "中（一般的な脆弱性）")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        HStack(spacing: 4) {
                            Text("P3")
                                .font(.caption2.bold())
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(SemanticColors.role("infoText").opacity(0.18), in: Capsule())
                                .foregroundStyle(SemanticColors.role("infoText"))
                            Text(english ? "Low (Info)" : "低（軽微・情報）")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
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
        let aspm = aspmRepos.first(where: { $0.id == repo.id || $0.repo == repo.name })
        return HStack(spacing: 12) {
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
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if let aspm, (aspm.p0 + aspm.p1 + aspm.p2 + aspm.p3) > 0 {
                HStack(spacing: 6) {
                    if aspm.p0 > 0 {
                        savedAnalysisTierPill(label: "P0", count: aspm.p0, color: SemanticColors.role("dangerText")) {
                            openDrilldown(tier: "P0", diagramId: repo.id, title: "\(repo.name) — P0")
                        }
                    }
                    if aspm.p1 > 0 {
                        savedAnalysisTierPill(label: "P1", count: aspm.p1, color: SemanticColors.role("warningText")) {
                            openDrilldown(tier: "P1", diagramId: repo.id, title: "\(repo.name) — P1")
                        }
                    }
                    if aspm.p2 > 0 {
                        savedAnalysisTierPill(label: "P2", count: aspm.p2, color: SemanticColors.role("actionText")) {
                            openDrilldown(tier: "P2", diagramId: repo.id, title: "\(repo.name) — P2")
                        }
                    }
                    if aspm.p3 > 0 {
                        savedAnalysisTierPill(label: "P3", count: aspm.p3, color: SemanticColors.role("infoText")) {
                            openDrilldown(tier: "P3", diagramId: repo.id, title: "\(repo.name) — P3")
                        }
                    }
                }
            } else {
                Label(english ? "\(repo.findings) findings" : "指摘 \(repo.findings)件",
                      systemImage: SemanticColors.severitySymbol(repo.severity))
                    .font(.callout).foregroundStyle(SemanticColors.severityColor(repo.severity))
            }

            Button {
                selection = ["repo:" + repo.id]
                coordinator.page = .audit
                coordinator.send("repository", value: repo.id)
                coordinator.send("page", value: WorkspacePage.audit.command)
            } label: {
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .help(english ? "Open saved audit for \(repo.name)" : "\(repo.name) の監査結果を開く")
        .contextMenu {
            repositoryContextMenu(for: repo)
        }
    }

    private func savedAnalysisTierPill(label: String, count: Int, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text("\(label): \(count)")
                .font(.caption2.bold().monospacedDigit())
                .foregroundStyle(color)
                .padding(.horizontal, 7)
                .padding(.vertical, 3)
                .background(color.opacity(0.16), in: Capsule())
        }
        .buttonStyle(.plain)
        .help(english ? "View \(label) findings (\(count))" : "\(label) の指摘を表示 (\(count)件)")
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

    @ViewBuilder
    private func commitMonitorBar() -> some View {
        GroupBox {
            HStack(spacing: 12) {
                Circle()
                    .fill(monitorEnabled ? SemanticColors.role("successText") : Color.secondary.opacity(0.5))
                    .frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(english ? "Auto Commit Monitor" : "新着コミット監視")
                            .font(.subheadline.weight(.semibold))
                        if monitorEnabled && monitorLaunchdInstalled {
                            Text(english ? "Background (launchd)" : "アプリ未起動時も監視 (launchd)")
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(SemanticColors.role("successText").opacity(0.14), in: Capsule())
                                .foregroundStyle(SemanticColors.role("successText"))
                        }
                        if !monitorLastCheckTime.isEmpty {
                            Text(
                                english
                                    ? "Last checked: \(monitorLastCheckTime)"
                                    : "最終確認: \(monitorLastCheckTime)"
                            )
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                        }
                    }
                    if !monitorSummary.isEmpty {
                        Text(monitorSummary)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    } else {
                        Text(
                            english
                                ? "Checks GitHub HEAD commits periodically and re-audits only updated repositories."
                                : "定期的に GitHub の HEAD コミットを確認し、更新があったリポジトリだけ自動再監査します。"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    }
                }
                Spacer(minLength: 0)
                Picker("", selection: Binding(
                    get: { monitorIntervalSec },
                    set: { newInterval in
                        monitorIntervalSec = newInterval
                        Task { await updateMonitorConfig(enabled: monitorEnabled, intervalSec: newInterval) }
                    }
                )) {
                    Text(english ? "5m" : "5分").tag(300)
                    Text(english ? "15m" : "15分").tag(900)
                    Text(english ? "30m" : "30分").tag(1800)
                    Text(english ? "1h" : "1時間").tag(3600)
                    Text(english ? "3h" : "3時間").tag(10800)
                    Text(english ? "6h" : "6時間").tag(21600)
                    Text(english ? "24h" : "24時間").tag(86400)
                }
                .labelsHidden()
                .frame(width: 96)
                .disabled(!backend.isReady)

                Toggle("", isOn: Binding(
                    get: { monitorEnabled },
                    set: { newEnabled in
                        monitorEnabled = newEnabled
                        Task { await updateMonitorConfig(enabled: newEnabled, intervalSec: monitorIntervalSec) }
                    }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .disabled(!backend.isReady)

                Button {
                    Task { await triggerMonitorCheckNow() }
                } label: {
                    if monitorChecking {
                        HStack(spacing: 5) {
                            ProgressView().controlSize(.small)
                            Text(english ? "Checking…" : "確認中…")
                        }
                    } else {
                        Label(english ? "Check now" : "今すぐ確認", systemImage: "arrow.triangle.2.circlepath")
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(monitorChecking || !backend.isReady)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }

    @ViewBuilder
    private func monitorUpdatesCard() -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label(
                        english ? "Resolved Risks from New Commits" : "新着コミットで解消された監査結果",
                        systemImage: "checkmark.seal.fill"
                    )
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(SemanticColors.role("successText"))
                    Spacer()
                }

                ForEach(Array(monitorUpdates.prefix(5))) { upd in
                    monitorUpdateRow(upd)
                }
            }
            .padding(12)
        }
    }

    @ViewBuilder
    private func monitorUpdateRow(_ upd: MonitorUpdateEvent) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(upd.repo)
                    .font(.subheadline.weight(.semibold))
                if !upd.oldCommit.isEmpty || !upd.newCommit.isEmpty {
                    Text("\(upd.oldCommit) → \(upd.newCommit)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if upd.resolvedCount > 0 {
                    Text(english ? "✓ \(upd.resolvedCount) resolved" : "✓ \(upd.resolvedCount)件解消")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(SemanticColors.role("successText").opacity(0.16), in: Capsule())
                        .foregroundStyle(SemanticColors.role("successText"))
                } else {
                    Text(english ? "Remaining: \(upd.findings)" : "残存指摘: \(upd.findings)件")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if upd.resolvedFindings.isEmpty {
                Text(
                    english
                        ? "No previously flagged findings were removed in this commit."
                        : "このコミットで解消された既存指摘はありません（現在の指摘: \(upd.findings)件）。"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(upd.resolvedFindings.prefix(8))) { item in
                        resolvedFindingRow(item)
                    }
                    if upd.resolvedCount > 8 {
                        Text(english ? "…and \(upd.resolvedCount - 8) more resolved" : "…ほか \(upd.resolvedCount - 8) 件解消")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.leading, 6)
            }
        }
        .padding(10)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.4)))
    }

    @ViewBuilder
    private func resolvedFindingRow(_ item: ResolvedFindingSummary) -> some View {
        let sevTint = SemanticColors.severityColor(item.severity)
        HStack(spacing: 6) {
            Text(item.severity.uppercased())
                .font(.caption2.weight(.bold))
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(sevTint.opacity(0.16), in: Capsule())
                .foregroundStyle(sevTint)
            Text(item.title)
                .font(.caption)
                .lineLimit(1)
            if !item.file.isEmpty {
                Text("(\(item.file))")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            if item.requiresRevoke {
                Text(english ? "Verify Revoked" : "要Revoke確認")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(SemanticColors.role("warningText").opacity(0.18), in: Capsule())
                    .foregroundStyle(SemanticColors.role("warningText"))
            }
        }
    }

    @ViewBuilder
    private func revocationChecklistCard() -> some View {
        let pendingCount = revocationChecks.filter { !$0.revokedConfirmed }.count
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Image(systemName: pendingCount > 0 ? "key.fill" : "checkmark.shield.fill")
                        .foregroundStyle(pendingCount > 0 ? SemanticColors.role("warningText") : SemanticColors.role("successText"))
                    Text(
                        english
                            ? "Git History & Provider Key Revocation Checklist"
                            : "Git 履歴残存・キー失効（Revoke / Rotate）確認"
                    )
                    .font(.subheadline.weight(.semibold))
                    Spacer()
                    Text(
                        pendingCount > 0
                            ? (english ? "\(pendingCount) pending" : "未確認 \(pendingCount)件")
                            : (english ? "All verified" : "すべて確認済み")
                    )
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(
                        (pendingCount > 0 ? SemanticColors.role("warningText") : SemanticColors.role("successText")).opacity(0.16),
                        in: Capsule()
                    )
                    .foregroundStyle(pendingCount > 0 ? SemanticColors.role("warningText") : SemanticColors.role("successText"))
                }
                Text(
                    english
                        ? "Even after removal from HEAD, keys remain in Git commit history. Confirm that each key has been revoked/rotated in AWS IAM, OpenAI, or RDS."
                        : "HEAD から削除されても過去コミット履歴にはキーが残るため、AWS IAM / OpenAI / RDS 等での無効化・変更が完了したらチェックを入れてください。"
                )
                .font(.caption)
                .foregroundStyle(.secondary)

                ForEach(revocationChecks.prefix(10)) { rev in
                    revocationRow(rev)
                }
            }
            .padding(12)
        }
    }

    @ViewBuilder
    private func revocationRow(_ rev: SecretRevocationItem) -> some View {
        HStack(spacing: 10) {
            Button {
                Task { await toggleRevocationConfirmation(key: rev.id, confirmed: !rev.revokedConfirmed) }
            } label: {
                Image(systemName: rev.revokedConfirmed ? "checkmark.square.fill" : "square")
                    .font(.title3)
                    .foregroundStyle(rev.revokedConfirmed ? SemanticColors.role("successText") : .secondary)
            }
            .buttonStyle(.plain)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(rev.repo)
                        .font(.caption.weight(.semibold))
                    if !rev.newCommit.isEmpty {
                        Text("HEAD: \(rev.newCommit)")
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    if !rev.file.isEmpty {
                        Text(rev.file)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                Text(rev.title)
                    .font(.caption)
                    .strikethrough(rev.revokedConfirmed, color: .secondary)
                    .foregroundStyle(rev.revokedConfirmed ? .secondary : .primary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if rev.revokedConfirmed {
                Text(english ? "Revoked ✓" : "Revoke済み ✓")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(SemanticColors.role("successText"))
            } else {
                Button(english ? "Mark Revoked" : "失効確認済みにする") {
                    Task { await toggleRevocationConfirmation(key: rev.id, confirmed: true) }
                }
                .buttonStyle(.bordered)
                .controlSize(.mini)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.4)))
    }

    private func applyMonitorStatusPayload(_ json: [String: Any]) {
        if let enabled = json["enabled"] as? Bool {
            monitorEnabled = enabled
        }
        if let interval = json["interval_sec"] as? Int {
            monitorIntervalSec = interval
        }
        monitorChecking = json["checking"] as? Bool ?? false
        if let checkTime = json["last_check_time"] as? String {
            monitorLastCheckTime = checkTime
        }
        if let summary = json["last_check_summary"] as? String {
            monitorSummary = summary
        }
        if let syncTime = json["last_sync_time"] as? String, !syncTime.isEmpty {
            lastCompletedSyncAt = syncTime
        }
        monitorLaunchdInstalled = json["launchd_installed"] as? Bool ?? false
        if let updates = json["detected_updates"] as? [[String: Any]] {
            var parsedEvents: [MonitorUpdateEvent] = []
            var newlyDetected: [MonitorUpdateEvent] = []
            for u in updates {
                let repo = u["repo"] as? String ?? ""
                let oldCommit = u["old_commit"] as? String ?? ""
                let newCommit = u["new_commit"] as? String ?? ""
                let detectedAt = u["detected_at"] as? String ?? ""
                let key = "\(repo)|\(newCommit)|\(detectedAt)"
                let rawResolved = u["resolved_findings"] as? [[String: Any]] ?? []
                let resolvedItems = rawResolved.map { rf in
                    ResolvedFindingSummary(
                        title: rf["title"] as? String ?? "",
                        file: rf["file"] as? String ?? "",
                        severity: rf["severity"] as? String ?? "info",
                        requiresRevoke: rf["requires_revoke"] as? Bool ?? false
                    )
                }
                let evt = MonitorUpdateEvent(
                    id: key,
                    repo: repo,
                    oldCommit: oldCommit,
                    newCommit: newCommit,
                    findings: u["findings"] as? Int ?? 0,
                    resolvedCount: u["resolved_count"] as? Int ?? resolvedItems.count,
                    resolvedHighCount: u["resolved_high_count"] as? Int ?? 0,
                    newCount: u["new_count"] as? Int ?? 0,
                    detectedAt: detectedAt,
                    resolvedFindings: resolvedItems
                )
                if !repo.isEmpty {
                    parsedEvents.append(evt)
                    if !seenMonitorUpdateKeys.contains(key) {
                        seenMonitorUpdateKeys.insert(key)
                        newlyDetected.append(evt)
                    }
                }
            }
            if !parsedEvents.isEmpty {
                monitorUpdates = parsedEvents
            }
            if !newlyDetected.isEmpty {
                coordinator.send("refresh")
                let first = newlyDetected[0]
                let bodyText: String
                if newlyDetected.count == 1 {
                    if first.resolvedCount > 0 {
                        bodyText = english
                            ? "\(first.repo) (\(first.newCommit)) — \(first.resolvedCount) findings resolved!"
                            : "\(first.repo) (\(first.newCommit)) — \(first.resolvedCount)件の指摘が解消されました！"
                    } else {
                        bodyText = english
                            ? "\(first.repo) (\(first.newCommit)) — \(first.findings) findings"
                            : "\(first.repo) (\(first.newCommit)) を再監査しました（指摘 \(first.findings)件）"
                    }
                } else {
                    let totalResolved = newlyDetected.reduce(0) { $0 + $1.resolvedCount }
                    bodyText = english
                        ? "\(newlyDetected.count) repositories updated (\(totalResolved) findings resolved)."
                        : "\(newlyDetected.count) 件のリポジトリを更新・再監査しました（\(totalResolved)件解消）。"
                }
                AppNotificationManager.sendAnalysisCompleted(
                    title: english ? "New Commit Re-audited" : "新着コミットを検知・再監査完了",
                    body: bodyText
                )
            }
        }
        if let rawRevocations = json["revocation_checks"] as? [[String: Any]] {
            revocationChecks = rawRevocations.compactMap { item in
                guard let key = item["key"] as? String, !key.isEmpty else { return nil }
                return SecretRevocationItem(
                    id: key,
                    repo: item["repo"] as? String ?? "",
                    title: item["title"] as? String ?? "",
                    file: item["file"] as? String ?? "",
                    severity: item["severity"] as? String ?? "critical",
                    newCommit: item["new_commit"] as? String ?? "",
                    resolvedAt: item["resolved_at"] as? String ?? "",
                    revokedConfirmed: item["revoked_confirmed"] as? Bool ?? false,
                    confirmedAt: item["confirmed_at"] as? String
                )
            }
        }
    }

    private func toggleRevocationConfirmation(key: String, confirmed: Bool) async {
        guard backend.isReady else { return }
        if let json = try? await requestJSON("/api/monitor/revoke", body: [
            "key": key,
            "confirmed": confirmed,
        ]) {
            applyMonitorStatusPayload(json)
        }
    }

    private func fetchMonitorStatus() async {
        guard backend.isReady else { return }
        if let json = try? await requestJSON("/api/monitor/status") {
            applyMonitorStatusPayload(json)
        }
    }

    private func updateMonitorConfig(enabled: Bool, intervalSec: Int) async {
        guard backend.isReady else { return }
        if let json = try? await requestJSON("/api/monitor/config", body: [
            "enabled": enabled,
            "interval_sec": intervalSec,
        ]) {
            applyMonitorStatusPayload(json)
        }
    }

    private func triggerMonitorCheckNow() async {
        guard backend.isReady && !monitorChecking else { return }
        monitorChecking = true
        if let json = try? await requestJSON("/api/monitor/check", body: [:]) {
            applyMonitorStatusPayload(json)
        }
        for _ in 0..<60 {
            try? await Task.sleep(for: .seconds(1))
            guard let status = try? await requestJSON("/api/monitor/status") else { break }
            applyMonitorStatusPayload(status)
            if !(status["checking"] as? Bool ?? false) {
                break
            }
        }
        monitorChecking = false
    }

    @ViewBuilder
    private func liveSyncProgressCard(_ progress: SyncProgressInfo) -> some View {
        let isRunning = progress.status != "completed"
        let etaLabel: String = {
            guard isRunning else {
                return english ? "Completed" : "完了"
            }
            guard let eta = progress.etaSeconds, eta > 0 else {
                return english ? "Estimating…" : "計測中…"
            }
            if eta >= 60 {
                let mins = eta / 60
                let secs = eta % 60
                return english ? "ETA: ~\(mins)m \(secs)s" : "残り目安: 約 \(mins)分\(secs)秒"
            }
            return english ? "ETA: ~\(eta)s" : "残り目安: 約 \(eta)秒"
        }()

        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    if isRunning {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(SemanticColors.role("successText"))
                    }
                    Text(
                        isRunning
                            ? (english ? "Live Security Audit Progress" : "リアルタイム監査ログ・進捗")
                            : (english ? "Audit Run Summary" : "今回の監査実行ログ")
                    )
                    .font(.subheadline.weight(.semibold))
                    Spacer()
                    Text("\(progress.completed) / \(max(1, progress.total))")
                        .font(.caption.monospacedDigit().weight(.semibold))
                        .foregroundStyle(SemanticColors.role("actionText"))
                    Text("· \(etaLabel)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    if !isRunning {
                        Button {
                            syncProgress = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .help(english ? "Dismiss" : "閉じる")
                    }
                }

                ProgressView(
                    value: Double(min(progress.completed, max(1, progress.total))),
                    total: Double(max(1, progress.total))
                )
                .tint(isRunning ? SemanticColors.role("actionText") : SemanticColors.role("successText"))

                if !progress.currentRepo.isEmpty || !progress.currentStage.isEmpty {
                    HStack(spacing: 6) {
                        if !progress.currentRepo.isEmpty {
                            Text(progress.currentRepo)
                                .font(.caption.monospaced().weight(.semibold))
                                .lineLimit(1)
                        }
                        if !progress.currentStage.isEmpty {
                            Text("— \(progress.currentStage)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                }

                if !progress.logs.isEmpty {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 3) {
                                ForEach(Array(progress.logs.enumerated()), id: \.offset) { idx, line in
                                    Text(line)
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(.secondary)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .id(idx)
                                }
                            }
                            .padding(8)
                        }
                        .frame(height: 108)
                        .background(Color(nsColor: .textBackgroundColor).opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(.separator.opacity(0.4)))
                        .onChange(of: progress.logs.count) { _, newCount in
                            if newCount > 0 {
                                withAnimation(.easeOut(duration: 0.15)) {
                                    proxy.scrollTo(newCount - 1, anchor: .bottom)
                                }
                            }
                        }
                    }
                }
            }
            .padding(12)
        }
    }

    private func reloadAndAnalyzeRepositories() async {
        guard !refreshingList else { return }
        refreshingList = true
        listRefreshNote = english ? "Starting analysis…" : "解析を開始しています…"
        syncProgress = SyncProgressInfo(
            status: "running",
            total: max(1, dashboardRepositories.count),
            completed: 0,
            currentRepo: "",
            currentStage: english ? "Preparing repositories…" : "対象リポジトリを準備中…",
            etaSeconds: nil,
            logs: [english ? "▶ Starting security audit…" : "▶ セキュリティ監査を開始しています…"]
        )
        defer { refreshingList = false }

        do {
            let syncResp = try await requestJSON("/api/sync", body: [:])
            let jobId = syncResp["job_id"] as? String ?? ""
            if !jobId.isEmpty {
                listRefreshNote = english ? "Analyzing repositories…" : "全リポジトリを解析中…"
                for attempt in 0..<1800 {
                    try? await Task.sleep(for: .seconds(1))
                    guard let statusResp = try? await requestJSON("/api/sync/status?job_id=\(jobId)") else {
                        continue
                    }
                    let status = statusResp["status"] as? String ?? ""
                    let total = statusResp["total"] as? Int ?? max(1, dashboardRepositories.count)
                    let completed = statusResp["completed"] as? Int ?? 0
                    let currentRepo = statusResp["current_repo"] as? String ?? ""
                    let currentStage = statusResp["current_stage"] as? String ?? ""
                    let etaSeconds = statusResp["eta_seconds"] as? Int
                    let logs = statusResp["logs"] as? [String] ?? []
                    if let syncTime = statusResp["last_sync_time"] as? String, !syncTime.isEmpty {
                        lastCompletedSyncAt = syncTime
                    }
                    syncProgress = SyncProgressInfo(
                        status: status,
                        total: total,
                        completed: completed,
                        currentRepo: currentRepo,
                        currentStage: currentStage,
                        etaSeconds: etaSeconds,
                        logs: logs
                    )
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
            formatter.dateFormat = "yyyy/MM/dd HH:mm:ss"
            let time = formatter.string(from: Date())
            if lastCompletedSyncAt == nil {
                let fullFmt = DateFormatter()
                fullFmt.dateFormat = "yyyy/MM/dd HH:mm:ss"
                lastCompletedSyncAt = fullFmt.string(from: Date())
            }
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

    private func exportAuditPdfReport(repo: String = "") async {
        guard !copyingHighRiskReport else { return }
        copyingHighRiskReport = true
        highRiskCopyStatus = nil
        defer { copyingHighRiskReport = false }

        do {
            let langParam = english ? "en" : "ja"
            let encodedRepo = repo.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
            let query = repo.isEmpty ? "lang=\(langParam)" : "lang=\(langParam)&repo=\(encodedRepo)"
            let json = try await requestJSON("/api/report/pdf-html?\(query)")
            guard let html = json["html"] as? String, !html.isEmpty else {
                highRiskCopyStatus = english ? "Failed to build PDF HTML" : "PDF テンプレート生成に失敗しました"
                return
            }

            let pdfData: Data = try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.main.async {
                    let helper = PdfWebViewRenderer()
                    helper.render(html: html) { result in
                        continuation.resume(with: result)
                    }
                }
            }

            let saveURL: URL? = await MainActor.run {
                let panel = NSSavePanel()
                panel.allowedContentTypes = [.pdf]
                let safeSlug = repo.isEmpty ? "RepoAUDT-All" : repo.replacingOccurrences(of: "/", with: "-")
                panel.nameFieldStringValue = "\(safeSlug)-Security-Audit-Report.pdf"
                panel.canCreateDirectories = true
                return panel.runModal() == .OK ? panel.url : nil
            }
            guard let targetURL = saveURL else { return }
            try pdfData.write(to: targetURL, options: .atomic)
            NSWorkspace.shared.activateFileViewerSelecting([targetURL])
            highRiskCopyStatus = english ? "✓ Saved PDF report" : "✓ PDF報告書を保存しました"
        } catch {
            highRiskCopyStatus = error.localizedDescription
        }
    }

    private func copySlackDigestReport() async {
        guard !copyingHighRiskReport else { return }
        copyingHighRiskReport = true
        highRiskCopyStatus = nil
        defer { copyingHighRiskReport = false }

        do {
            let langParam = english ? "en" : "ja"
            let json = try await requestJSON("/api/report/slack?lang=\(langParam)")
            let markdown = json["markdown"] as? String ?? ""
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(markdown, forType: .string)
            highRiskCopyStatus = english ? "✓ Copied Slack digest" : "✓ Slackサマリーをコピーしました"
            Task {
                try? await Task.sleep(for: .seconds(4))
                if highRiskCopyStatus != nil {
                    highRiskCopyStatus = nil
                }
            }
        } catch {
            highRiskCopyStatus = error.localizedDescription
        }
    }

    private func copyHighRiskReport() async {
        guard !copyingHighRiskReport else { return }
        copyingHighRiskReport = true
        highRiskCopyStatus = nil
        defer { copyingHighRiskReport = false }

        do {
            let state = try await requestJSON("/api/state")
            let diagrams = state["diagrams"] as? [[String: Any]] ?? []
            var sections: [String] = []
            var crossRepoRows: [(tierRank: Int, tier: String, repo: String, title: String, file: String, action: String)] = []
            var totalHighFindings = 0
            var affectedRepos = 0

            for d in diagrams {
                if (d["is_root"] as? Bool) == true { continue }
                let repoName = (d["repo"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                let githubUrl = (d["github_url"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                let rev = d["source_revision"] as? [String: Any]
                let commitHash = (rev?["commit_sha"] as? String) ?? (d["commit_hash"] as? String ?? "")
                let cr = d["coderabbit"] as? [String: Any]
                let actionItems = cr?["action_items"] as? [[String: Any]] ?? []
                let findings = cr?["findings"] as? [[String: Any]] ?? []

                var seenKeys = Set<String>()
                var highItems: [[String: Any]] = []
                for item in actionItems + findings {
                    if (item["suppressed"] as? Bool) == true { continue }
                    let sev = (item["severity"] as? String ?? "").lowercased()
                    let tier = (item["priority_tier"] as? String ?? "").uppercased()
                    if !tier.isEmpty {
                        guard tier == "P0" || tier == "P1" else { continue }
                    } else {
                        guard sev == "critical" || sev == "high" else { continue }
                    }
                    let title = item["title"] as? String ?? ""
                    let file = item["file"] as? String ?? ""
                    let cve = item["cve"] as? String ?? ""
                    let fp = (item["fingerprint"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                    let key = fp.isEmpty ? "\(title)|\(file)|\(cve)" : fp
                    if seenKeys.contains(key) { continue }
                    seenKeys.insert(key)
                    highItems.append(item)
                }

                highItems.sort { lhs, rhs in
                    let rank: ([String: Any]) -> Int = { it in
                        switch (it["priority_tier"] as? String ?? "P2").uppercased() {
                        case "P0": return 0
                        case "P1": return 1
                        case "P2": return 2
                        default: return 3
                        }
                    }
                    return rank(lhs) < rank(rhs)
                }

                guard !highItems.isEmpty else { continue }
                affectedRepos += 1
                totalHighFindings += highItems.count

                var repoLines: [String] = []
                repoLines.append("## \(repoName.isEmpty ? githubUrl : repoName) (\(highItems.count))")
                if !githubUrl.isEmpty { repoLines.append("- **Repository URL**: \(githubUrl)") }
                if !commitHash.isEmpty { repoLines.append("- **Commit**: `\(commitHash)`") }

                for (idx, item) in highItems.enumerated() {
                    let sev = (item["severity"] as? String ?? "high").uppercased()
                    let tier = (item["priority_tier"] as? String ?? "").uppercased()
                    let tierPrefix = tier.isEmpty ? "" : "[\(tier)] "
                    let kevTag = (item["in_cisa_kev"] as? Bool) == true ? " 🔥[CISA KEV]" : ""
                    let newTag = (item["is_new"] as? Bool) == true ? " 🆕[NEW]" : ""
                    let title = item["title"] as? String ?? "Finding"
                    let file = item["file"] as? String ?? ""
                    let desc = item["desc"] as? String ?? (item["comment"] as? String ?? "")
                    let reason = item["priority_reason"] as? String ?? ""
                    let reachability = item["reachability"] as? String ?? ""
                    let diff = item["diff"] as? String ?? ""
                    let fixCmd = item["fix_cmd"] as? String ?? ""
                    let officialSource = item["official_source"] as? String ?? ""
                    let displayRepo = repoName.isEmpty ? githubUrl : repoName
                    let tRank = tier == "P0" ? 0 : 1
                    let shortFile = file.components(separatedBy: " (Target:").first ?? file
                    let isInspectOnlyCmd = fixCmd.hasPrefix("sed -n") || fixCmd.hasPrefix("cat ") || fixCmd.hasPrefix("head ") || fixCmd.hasPrefix("grep ")
                    let fallbackAction: String = {
                        if tier == "P0" {
                            return english ? "Revoke/rotate immediately & purge from Git" : "即時無効化・ローテーション＆Git履歴から削除"
                        }
                        return reason.isEmpty ? (english ? "Upgrade to fixed version" : "安全版へ更新・修正") : reason
                    }()
                    let shortAction = (fixCmd.isEmpty || isInspectOnlyCmd) ? fallbackAction : fixCmd
                    crossRepoRows.append((
                        tierRank: tRank,
                        tier: tier.isEmpty ? (sev == "critical" ? "P0" : "P1") : tier,
                        repo: displayRepo,
                        title: title.replacingOccurrences(of: "|", with: "/"),
                        file: shortFile.replacingOccurrences(of: "|", with: "/"),
                        action: shortAction.replacingOccurrences(of: "|", with: "/").replacingOccurrences(of: "\n", with: " ")
                    ))

                    repoLines.append("")
                    let conf = ((item["confidence"] as? String) ?? "medium").capitalized
                    let evList = (item["priority_evidence"] as? [String]) ?? []
                    let evStr = evList.isEmpty ? "" : " · Evidence: " + evList.joined(separator: ", ")
                    repoLines.append("### \(idx + 1). \(tierPrefix)(Confidence: \(conf)) [\(sev)]\(kevTag)\(newTag) \(title)")
                    if !reason.isEmpty { repoLines.append("- **Priority Reason**: \(reason)\(evStr)") }
                    if !reachability.isEmpty { repoLines.append("- **Reachability**: `\(reachability)`") }
                    if !file.isEmpty { repoLines.append("- **File**: `\(file)`") }
                    if !officialSource.isEmpty { repoLines.append("- **Reference**: \(officialSource)") }
                    if !desc.isEmpty { repoLines.append("- **Details**: \(desc)") }
                    if !diff.isEmpty {
                        repoLines.append("```diff\n\(diff)\n```")
                    }
                    if !fixCmd.isEmpty {
                        repoLines.append("```bash\n\(fixCmd)\n```")
                    }
                }
                sections.append(repoLines.joined(separator: "\n"))
            }

            let header = english
                ? "# 🛡️ RepoAUDT Mac — Critical & High-Risk Audit Report\n\n- **Affected Repositories**: \(affectedRepos)\n- **Total Critical / High Findings**: \(totalHighFindings)\n"
                : "# 🛡️ RepoAUDT Mac — 重大・高リスク一括監査レポート\n\n- **対象リポジトリ数**: \(affectedRepos) 件\n- **重大・高リスク指摘合計**: \(totalHighFindings) 件\n"
            var summaryTable = ""
            if !crossRepoRows.isEmpty {
                let sortedRows = crossRepoRows.sorted { $0.tierRank < $1.tierRank }
                var tbl: [String] = [
                    english ? "## 🚨 Cross-Repository P0 / P1 Top Summary" : "## 🚨 全リポジトリ横断 P0 / P1 サマリー",
                    "",
                    english ? "| Priority | Repository | Finding | Target File | Recommended Action |" : "| 優先度 | リポジトリ | 指摘タイトル | 対象ファイル | 推奨アクション |",
                    "| --- | --- | --- | --- | --- |"
                ]
                for row in sortedRows {
                    tbl.append("| **\(row.tier)** | `\(row.repo)` | \(row.title) | `\(row.file)` | `\(row.action)` |")
                }
                summaryTable = "\n" + tbl.joined(separator: "\n") + "\n"
            }
            let report = sections.isEmpty
                ? header + (english ? "\nNo Critical or High findings." : "\n重大・高リスクの指摘はありません。")
                : header + summaryTable + "\n---\n\n" + sections.joined(separator: "\n\n---\n\n")

            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(report, forType: .string)

            highRiskCopyStatus = english
                ? "✓ Copied (\(totalHighFindings) findings)"
                : "✓ コピーしました (\(totalHighFindings)件)"
            Task {
                try? await Task.sleep(for: .seconds(4))
                if highRiskCopyStatus != nil {
                    highRiskCopyStatus = nil
                }
            }
        } catch {
            highRiskCopyStatus = error.localizedDescription
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

    private func refreshAspmPortfolio() async {
        guard backend.isReady else { return }
        do {
            let json = try await requestJSON("/api/aspm")
            guard let rawRepos = json["repos"] as? [[String: Any]] else { return }
            let parsed: [AspmRepoItem] = rawRepos.map { d in
                let cov = d["coverage"] as? [String: [String: Any]] ?? [:]
                let icon: (String) -> String = { key in
                    let st = (cov[key]?["status"] as? String) ?? "unscanned"
                    switch st {
                    case "clean": return "✅"
                    case "issues": return "⚠️"
                    case "not_applicable": return "➖"
                    default: return "⬜"
                    }
                }
                let counts = d["counts"] as? [String: Any] ?? [:]
                let compact = "Sec:\(icon("secrets")) SCA:\(icon("sca")) SAST:\(icon("sast")) CI:\(icon("cicd")) IaC:\(icon("iac")) GH:\(icon("posture"))"
                return AspmRepoItem(
                    id: (d["id"] as? String) ?? UUID().uuidString,
                    repo: (d["repo"] as? String) ?? "Repository",
                    criticality: (d["criticality"] as? String) ?? "tier2_internal",
                    riskScore: (d["risk_score"] as? Int) ?? 0,
                    releaseGate: (d["release_gate"] as? String) ?? "PASS",
                    gateReasons: (d["gate_reasons"] as? [String]) ?? [],
                    coverageCompact: compact,
                    p0: (counts["P0"] as? Int) ?? 0,
                    p1: (counts["P1"] as? Int) ?? 0,
                    p2: (counts["P2"] as? Int) ?? 0,
                    p3: (counts["P3"] as? Int) ?? 0
                )
            }
            let rawHistory = json["history"] as? [[String: Any]] ?? []
            let parsedHistory: [AspmHistoryPoint] = rawHistory.enumerated().map { idx, h in
                let repoScore = (h["risk_score"] as? Int) ?? 0
                let orgScore = h["org_risk_score"] as? Int
                return AspmHistoryPoint(
                    id: "\(idx)-\((h["timestamp"] as? String) ?? "")",
                    timestamp: (h["timestamp"] as? String) ?? "",
                    repo: (h["repo"] as? String) ?? "",
                    riskScore: orgScore ?? repoScore,
                    repoRiskScore: repoScore,
                    orgRiskScore: orgScore,
                    repoDelta: (h["repo_delta"] as? Int) ?? 0,
                    p0Count: (h["p0_count"] as? Int) ?? 0,
                    p1Count: (h["p1_count"] as? Int) ?? 0,
                    newCount: (h["new_since_prev"] as? Int) ?? 0,
                    resolvedCount: (h["resolved_since_prev"] as? Int) ?? 0
                )
            }
            await MainActor.run {
                aspmRepos = parsed
                aspmHistory = parsedHistory
            }
        } catch {
            // Non-fatal dashboard enhancement
        }
    }

    private func openDrilldown(tier: String?, diagramId: String? = nil, title: String) {
        drilldownFilter = DashboardDrilldownFilter(tier: tier, title: title)
        loadingDrilldown = true
        drilldownItems = []
        Task {
            defer { Task { @MainActor in loadingDrilldown = false } }
            guard let state = try? await requestJSON("/api/state"),
                  let diagrams = state["diagrams"] as? [[String: Any]] else { return }
            var collected: [DrilldownFindingItem] = []
            for d in diagrams {
                if (d["is_root"] as? Bool) == true { continue }
                let did = (d["id"] as? String) ?? ""
                if let targetDiagramId = diagramId, did != targetDiagramId { continue }
                let repoName = (d["repo"] as? String) ?? (d["github_url"] as? String) ?? "Repository"
                let cr = d["coderabbit"] as? [String: Any]
                let actions = cr?["action_items"] as? [[String: Any]] ?? []
                var seen = Set<String>()
                for it in actions {
                    if (it["suppressed"] as? Bool) == true { continue }
                    let t = ((it["priority_tier"] as? String) ?? "P2").uppercased()
                    if let filterTier = tier {
                        if filterTier == "HIGH_CRIT" {
                            if t != "P0" && t != "P1" { continue }
                        } else if t != filterTier {
                            continue
                        }
                    }
                    let titleStr = (it["title"] as? String) ?? ""
                    let fileStr = ((it["file"] as? String) ?? "").components(separatedBy: " (Target:").first ?? ""
                    let key = "\(did)|\(titleStr)|\(fileStr)"
                    if seen.contains(key) { continue }
                    seen.insert(key)
                    collected.append(DrilldownFindingItem(
                        id: key,
                        diagramId: did,
                        repoName: repoName,
                        tier: t,
                        title: titleStr,
                        file: fileStr,
                        reason: (it["priority_reason"] as? String) ?? "",
                        fingerprint: (it["fingerprint"] as? String) ?? "",
                        description: (it["description"] as? String) ?? "",
                        fixCommand: (it["fix_command"] as? String) ?? ""
                    ))
                }
            }
            let rank: (String) -> Int = { t in
                switch t {
                case "P0": return 0
                case "P1": return 1
                case "P2": return 2
                default: return 3
                }
            }
            collected.sort { rank($0.tier) < rank($1.tier) }
            let initialGroups = groupedDrilldownItems(collected)
            await MainActor.run {
                drilldownItems = collected
                expandedDrilldownGroups = Set(initialGroups.prefix(8).map(\.id))
                drilldownCopyNotice = nil
            }
        }
    }

    private func openDrilldownFinding(_ item: DrilldownFindingItem) {
        let targetId = item.diagramId
        let payloadStr = (try? JSONSerialization.data(withJSONObject: [
            "fingerprint": item.fingerprint,
            "title": item.title,
            "file": item.file
        ])).flatMap { String(data: $0, encoding: .utf8) } ?? item.fingerprint
        drilldownFilter = nil
        if !targetId.isEmpty {
            selection = ["repo:\(targetId)"]
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.18) {
                coordinator.send("focus-finding", value: payloadStr)
            }
        }
    }

    private func normalizedFindingGroupTitle(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.contains("[シークレット設定ファイル漏洩]") {
            return "🚨 [シークレット設定ファイル漏洩] 認証情報を含む設定ファイルのコミット"
        }
        // Strip trailing file:line or filename in parentheses, e.g. " (config.ts:6)" or " (waiphyo-account.csv:5)"
        if let range = s.range(of: #"\s*\([^()]*:\d+\)$"#, options: .regularExpression) {
            s.removeSubrange(range)
        } else if let range = s.range(of: #"\s*\([^()]*\.(ts|tsx|js|jsx|json|csv|py|yml|yaml|env|lock|md|sh|swift|go|rb|php|java|kt|rs)\)$"#, options: [.regularExpression, .caseInsensitive]) {
            s.removeSubrange(range)
        }
        return s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func groupedDrilldownItems(_ items: [DrilldownFindingItem]) -> [DrilldownFindingGroup] {
        var order: [String] = []
        var buckets: [String: [DrilldownFindingItem]] = [:]
        var titles: [String: String] = [:]
        var tiers: [String: String] = [:]

        for item in items {
            let groupTitle = normalizedFindingGroupTitle(item.title)
            let key = "\(item.tier)|\(groupTitle.lowercased())"
            if buckets[key] == nil {
                order.append(key)
                buckets[key] = []
                titles[key] = groupTitle
                tiers[key] = item.tier
            }
            buckets[key]?.append(item)
        }

        let rank: (String) -> Int = { t in
            switch t {
            case "P0": return 0
            case "P1": return 1
            case "P2": return 2
            default: return 3
            }
        }

        return order.compactMap { key in
            guard let groupItems = buckets[key], !groupItems.isEmpty else { return nil }
            return DrilldownFindingGroup(
                id: key,
                tier: tiers[key] ?? "P2",
                title: titles[key] ?? groupItems[0].title,
                items: groupItems
            )
        }.sorted { lhs, rhs in
            let r1 = rank(lhs.tier), r2 = rank(rhs.tier)
            if r1 != r2 { return r1 < r2 }
            return lhs.items.count > rhs.items.count
        }
    }

    private func copyDrilldownFixPrompt(for groups: [DrilldownFindingGroup]) {
        guard !groups.isEmpty else { return }
        let totalCount = groups.reduce(0) { $0 + $1.items.count }
        var lines: [String] = [
            english
                ? "# Batch Security Remediation Request (\(totalCount) findings across \(groups.count) group(s))"
                : "# セキュリティ指摘 一括修正依頼（\(groups.count)グループ / 計\(totalCount)件）",
            "",
            english
                ? "Please fix all occurrences listed below together, keeping existing behavior intact and verifying each repository after remediation."
                : "以下の同種・類似のセキュリティ指摘をまとめて修正してください。既存の動作を壊さないように対応し、必要に応じて認証情報のローテーション・環境変数化・依存パッケージ更新等を実施してください。"
        ]

        for (idx, group) in groups.enumerated() {
            lines.append("")
            lines.append("## \(idx + 1). [\(group.tier)] \(group.title) (\(group.items.count)\(english ? " items" : "件") / \(group.repoCount)\(english ? " repos" : "リポジトリ"))")
            if let reason = group.items.first(where: { !$0.reason.isEmpty })?.reason {
                lines.append("- **\(english ? "Priority Reason" : "優先理由")**: \(reason)")
            }
            if let desc = group.items.first(where: { !$0.description.isEmpty })?.description {
                lines.append("- **\(english ? "Details" : "詳細")**: \(desc)")
            }
            lines.append("- **\(english ? "Target Locations" : "対象箇所")**:")
            for item in group.items {
                let loc = item.file.isEmpty ? item.title : item.file
                let cmd = item.fixCommand.isEmpty ? "" : " (`\(item.fixCommand)`)"
                lines.append("  - `\(item.repoName)` · `\(loc)`\(cmd)")
            }
        }

        let prompt = lines.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(prompt, forType: .string)

        let notice = english
            ? "Copied batch fix request (\(totalCount) items)"
            : "一括修正依頼プロンプトをコピーしました（\(totalCount)件）"
        drilldownCopyNotice = notice
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            if drilldownCopyNotice == notice {
                drilldownCopyNotice = nil
            }
        }
    }
}

private struct DashboardDrilldownFilter: Identifiable {
    let id = UUID()
    let tier: String?
    let title: String
}

private struct DrilldownFindingGroup: Identifiable {
    let id: String
    let tier: String
    let title: String
    let items: [DrilldownFindingItem]

    var repoCount: Int {
        Set(items.map(\.repoName)).count
    }

    var tierColor: Color {
        switch tier {
        case "P0": return SemanticColors.role("dangerText")
        case "P1": return SemanticColors.role("warningText")
        case "P2": return SemanticColors.role("actionText")
        default: return SemanticColors.role("infoText")
        }
    }
}

private struct DrilldownFindingItem: Identifiable {
    let id: String
    let diagramId: String
    let repoName: String
    let tier: String
    let title: String
    let file: String
    let reason: String
    let fingerprint: String
    var description: String = ""
    var fixCommand: String = ""

    var tierColor: Color {
        switch tier {
        case "P0": return SemanticColors.role("dangerText")
        case "P1": return SemanticColors.role("warningText")
        case "P2": return SemanticColors.role("actionText")
        default: return SemanticColors.role("infoText")
        }
    }
}

private struct AspmHistoryPoint: Identifiable {
    let id: String
    let timestamp: String
    let repo: String
    let riskScore: Int
    let repoRiskScore: Int
    let orgRiskScore: Int?
    let repoDelta: Int
    let p0Count: Int
    let p1Count: Int
    let newCount: Int
    let resolvedCount: Int

    var shortTimestamp: String {
        guard !timestamp.isEmpty else { return "-" }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let date = iso.date(from: timestamp) ?? ISO8601DateFormatter().date(from: timestamp)
        guard let date else { return String(timestamp.prefix(16)) }
        let fmt = DateFormatter()
        fmt.dateFormat = "MM/dd HH:mm"
        return fmt.string(from: date)
    }
}

private struct AspmRepoItem: Identifiable {
    let id: String
    let repo: String
    let criticality: String
    let riskScore: Int
    let releaseGate: String
    let gateReasons: [String]
    let coverageCompact: String
    let p0: Int
    let p1: Int
    let p2: Int
    let p3: Int

    var gateEmoji: String {
        switch releaseGate {
        case "BLOCK": return "🔴"
        case "WARN": return "🟡"
        default: return "🟢"
        }
    }

    var gateColor: Color {
        switch releaseGate {
        case "BLOCK": return SemanticColors.role("dangerText")
        case "WARN": return SemanticColors.role("warningText")
        default: return SemanticColors.role("successText")
        }
    }

    func criticalityLabel(english: Bool) -> String {
        switch criticality {
        case "tier1_prod": return english ? "Tier 1 (Prod)" : "Tier 1 (本番)"
        case "tier3_demo": return english ? "Tier 3 (Demo)" : "Tier 3 (デモ)"
        default: return english ? "Tier 2 (Internal)" : "Tier 2 (社内)"
        }
    }
}

extension Notification.Name {
    static let repoAudtExportPdf = Notification.Name("RepoAUDTExportPdfNotification")
}

private final class PdfWebViewRenderer: NSObject, WKNavigationDelegate {
    private var webView: WKWebView?
    private var completion: ((Result<Data, Error>) -> Void)?
    private var selfRetain: PdfWebViewRenderer?

    func render(html: String, completion: @escaping (Result<Data, Error>) -> Void) {
        self.selfRetain = self
        self.completion = completion
        let config = WKWebViewConfiguration()
        let wv = WKWebView(frame: NSRect(x: 0, y: 0, width: 794, height: 1123), configuration: config)
        wv.navigationDelegate = self
        self.webView = wv
        wv.loadHTMLString(html, baseURL: nil)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let pdfConfig = WKPDFConfiguration()
        pdfConfig.rect = CGRect(x: 0, y: 0, width: 595.28, height: 841.89)
        webView.createPDF(configuration: pdfConfig) { [weak self] result in
            guard let self else { return }
            let cb = self.completion
            self.completion = nil
            self.webView = nil
            self.selfRetain = nil
            cb?(result)
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finishWithError(error)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finishWithError(error)
    }

    private func finishWithError(_ error: Error) {
        let cb = completion
        completion = nil
        webView = nil
        selfRetain = nil
        cb?(.failure(error))
    }
}
