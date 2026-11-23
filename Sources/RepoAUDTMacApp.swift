import AppKit
import Foundation
import SwiftUI
import UserNotifications
import WebKit

enum AppNotificationManager {
    static func requestAuthorization() {
        guard Bundle.main.bundleIdentifier != nil else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    static func sendAnalysisCompleted(title: String, body: String) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: "repoaudt-analysis-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                NSLog("Failed to deliver analysis notification: \(error)")
            }
        }
    }
}

@MainActor
final class BackendServerManager: ObservableObject {
    static let shared = BackendServerManager()

    private var serverProcess: Process?
    private var isStopping: Bool = false
    private var restartCount: Int = 0
    private let maxAutoRestarts: Int = 5
    @Published private(set) var port: Int = 18765
    @Published private(set) var isReady: Bool = false

    private init() {}

    func startIfNeeded() {
        isStopping = false
        if checkPortOpen(port: port) {
            isReady = true
            return
        }

        guard let resourcePath = Bundle.main.resourcePath else {
            return
        }
        let scriptPath = (resourcePath as NSString).appendingPathComponent("backend/server.py")
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            return
        }

        let proc = Process()
        let pythonCandidates = [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3"
        ]
        let chosenPython = pythonCandidates.first { FileManager.default.isExecutableFile(atPath: $0) } ?? "/usr/bin/python3"

        proc.executableURL = URL(fileURLWithPath: chosenPython)
        proc.arguments = ["-B", scriptPath]

        var env = ProcessInfo.processInfo.environment
        let extraPaths = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        if let existingPath = env["PATH"] {
            env["PATH"] = "\(extraPaths):\(existingPath)"
        } else {
            env["PATH"] = extraPaths
        }
        env["REPOAUDT_PORT"] = String(port)
        env["REPOCHEX_PORT"] = String(port)
        env["REPOCHECKER_PORT"] = String(port)
        env["PYTHONUNBUFFERED"] = "1"
        proc.environment = env

        proc.terminationHandler = { [weak self] terminatedProc in
            Task { @MainActor in
                guard let self = self else { return }
                if self.serverProcess === terminatedProc {
                    self.serverProcess = nil
                }
                guard !self.isStopping, self.restartCount < self.maxAutoRestarts else { return }
                self.restartCount += 1
                try? await Task.sleep(nanoseconds: 500_000_000)
                if !self.isStopping {
                    self.startIfNeeded()
                }
            }
        }

        do {
            try proc.run()
            self.serverProcess = proc
        } catch {
            NSLog("Failed to start RepoAUDT Mac backend server: \(error)")
        }

        Task {
            for _ in 0..<30 {
                if checkPortOpen(port: self.port) {
                    self.isReady = true
                    return
                }
                try? await Task.sleep(nanoseconds: 150_000_000)
            }
            self.isReady = true
        }
    }

    func stop() {
        isStopping = true
        if let proc = serverProcess, proc.isRunning {
            proc.terminate()
        }
        serverProcess = nil
    }

    private func checkPortOpen(port: Int) -> Bool {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}

@MainActor
final class WebViewCoordinator: NSObject, ObservableObject, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    @Published var page: WorkspacePage = .dashboard
    @Published private(set) var repositories: [WorkspaceRepository] = []
    @Published private(set) var ready = false
    @Published private(set) var loadError: String?
    var language = "ja"
    private var pageLoaded = false

    func send(_ command: String, value: String = "", completion: (() -> Void)? = nil) {
        guard pageLoaded else {
            completion?()
            return
        }
        let script = """
        const previous = window.nativeWorkspaceQueue || Promise.resolve();
        const task = previous.catch(() => {}).then(() => nativeWorkspaceCommand(command, value));
        window.nativeWorkspaceQueue = task;
        await task;
        return null;
        """
        self.webView?.callAsyncJavaScript(script, arguments: ["command": command, "value": value],
                                    in: nil, in: .page) { [weak self] result in
            if case .failure(let error) = result {
                self?.loadError = (error as NSError).userInfo["WKJavaScriptExceptionMessage"] as? String ?? error.localizedDescription
                self?.ready = false
            }
            completion?()
        }
    }

    func reload() {
        loadError = nil
        ready = false
        pageLoaded = false
        webView?.reload()
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame,
              message.frameInfo.request.url?.host == "127.0.0.1" else { return }
        if message.name == "notify" {
            if let dict = message.body as? [String: Any] {
                let title = dict["title"] as? String ?? "RepoAUDT Mac"
                let body = dict["body"] as? String ?? (language == "en" ? "Repository analysis completed." : "リポジトリの解析が完了しました。")
                AppNotificationManager.sendAnalysisCompleted(title: title, body: body)
            }
            return
        }
        guard message.name == "workspace",
              let data = try? JSONSerialization.data(withJSONObject: message.body),
              let snapshot = try? JSONDecoder().decode(WorkspaceSnapshot.self, from: data) else { return }
        // Keep a single sidebar row for each saved repository.
        var seen = Set<String>()
        repositories = snapshot.repositories.filter { seen.insert($0.id).inserted }
        if ![WorkspacePage.dashboard, .ai, .mcp, .system].contains(page), let mode = snapshot.page {
            switch mode {
            case "arch": page = .architecture
            case "seq": page = .sequence
            case "coderabbit": page = .audit
            case "chat": page = .chat
            default: break
            }
        }
        ready = true
        loadError = nil
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        pageLoaded = true
        send("language", value: language)
        send("page", value: page.command)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        ready = false
        loadError = error.localizedDescription
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        ready = false
        loadError = error.localizedDescription
    }

    weak var webView: WKWebView?

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }

        if let host = url.host, host != "127.0.0.1" && host != "localhost" {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        if let url = navigationAction.request.url {
            NSWorkspace.shared.open(url)
        }
        return nil
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptAlertPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping () -> Void
    ) {
        let alert = NSAlert()
        alert.messageText = "RepoAUDT Mac"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
        completionHandler()
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptConfirmPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (Bool) -> Void
    ) {
        let alert = NSAlert()
        alert.messageText = "RepoAUDT Mac"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "キャンセル")
        let response = alert.runModal()
        completionHandler(response == .alertFirstButtonReturn)
    }
}

struct PortalWebView: NSViewRepresentable {
    let url: URL
    let coordinator: WebViewCoordinator

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "developerExtrasEnabled")
        config.userContentController.add(coordinator, name: "workspace")
        config.userContentController.add(coordinator, name: "notify")
        config.userContentController.addUserScript(WKUserScript(
            source: "document.documentElement.classList.add('native-host')",
            injectionTime: .atDocumentStart, forMainFrameOnly: true))

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.navigationDelegate = coordinator
        wv.uiDelegate = coordinator
        wv.setValue(false, forKey: "drawsBackground")
        coordinator.webView = wv
        wv.load(URLRequest(url: url))
        return wv
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    let coordinator = WebViewCoordinator()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        if Bundle.main.bundleIdentifier != nil {
            UNUserNotificationCenter.current().delegate = self
            AppNotificationManager.requestAuthorization()
        }
        if let iconPath = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let iconImg = NSImage(contentsOfFile: iconPath) {
            NSApp.applicationIconImage = iconImg
        }
        BackendServerManager.shared.startIfNeeded()
        NSApp.activate(ignoringOtherApps: true)
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    func applicationWillTerminate(_ notification: Notification) {
        BackendServerManager.shared.stop()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

@main
struct RepoAUDTMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup("RepoAUDT Mac") {
            MainContentView(coordinator: appDelegate.coordinator)
                .frame(minWidth: 900, minHeight: 620)
        }
        .defaultSize(width: 1180, height: 800)
        .commands {
            TextEditingCommands()
            CommandGroup(replacing: .newItem) {
                Button("GitHub URLを追加分析 / リスト管理...") {
                    appDelegate.coordinator.page = .audit
                    appDelegate.coordinator.send("analyze")
                }
                .keyboardShortcut("n", modifiers: [.command])

                Button("AI APIキー & 脆弱性監査設定 (管理画面)...") {
                    appDelegate.coordinator.page = .audit
                    appDelegate.coordinator.send("settings")
                }
                .keyboardShortcut(",", modifiers: [.command])

                Button("要対応アラート一覧を表示") {
                    appDelegate.coordinator.page = .audit
                    appDelegate.coordinator.webView?.evaluateJavaScript("openActionRequiredHubModal()", completionHandler: nil)
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])

                Button("死活監視モニターを開く") {
                    appDelegate.coordinator.page = .audit
                    appDelegate.coordinator.webView?.evaluateJavaScript("openHealthModal()", completionHandler: nil)
                }
                .keyboardShortcut("h", modifiers: [.command, .shift])
            }
        }
    }
}
