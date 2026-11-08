import AppKit
import Foundation
import SwiftUI
import WebKit

@MainActor
final class BackendServerManager: ObservableObject {
    static let shared = BackendServerManager()

    private var serverProcess: Process?
    @Published private(set) var port: Int = 18765
    @Published private(set) var isReady: Bool = false

    private init() {}

    func startIfNeeded() {
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
        proc.arguments = [scriptPath]

        var env = ProcessInfo.processInfo.environment
        let extraPaths = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        if let existingPath = env["PATH"] {
            env["PATH"] = "\(extraPaths):\(existingPath)"
        } else {
            env["PATH"] = extraPaths
        }
        env["REPOCHEX_PORT"] = String(port)
        env["REPOCHECKER_PORT"] = String(port)
        env["PYTHONUNBUFFERED"] = "1"
        proc.environment = env

        do {
            try proc.run()
            self.serverProcess = proc
        } catch {
            NSLog("Failed to start RepoChex backend server: \(error)")
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
final class WebViewCoordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
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
        alert.messageText = "RepoChex"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
        completionHandler()
    }
}

struct PortalWebView: NSViewRepresentable {
    let url: URL
    let coordinator: WebViewCoordinator

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "developerExtrasEnabled")

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

struct MainContentView: View {
    @ObservedObject var backend = BackendServerManager.shared
    let coordinator: WebViewCoordinator

    var body: some View {
        ZStack {
            Color(red: 0.04, green: 0.06, blue: 0.11).ignoresSafeArea()
            if backend.isReady, let url = URL(string: "http://127.0.0.1:\(backend.port)/index.html") {
                PortalWebView(url: url, coordinator: coordinator)
            } else {
                VStack(spacing: 14) {
                    ProgressView()
                        .controlSize(.large)
                    Text("RepoChex エンジンを起動中...")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundColor(.white)
                    Text("ローカルCodeRabbit・脆弱性監査 (MCP/Skills) & Mermaid構成図エンジンを初期化しています")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                Button(action: {
                    coordinator.webView?.evaluateJavaScript("openAnalyzeModal()", completionHandler: nil)
                }) {
                    Label("GitHub追加・リスト管理", systemImage: "plus.magnifyingglass")
                }
                .help("GitHub組織/リポジトリURLの追加分析と保有リストの管理・削除を行います (⌘N)")

                Button(action: {
                    coordinator.webView?.evaluateJavaScript("openAdminSettingsModal()", completionHandler: nil)
                }) {
                    Label("AIキー・監査設定", systemImage: "key.radiowaves.forward.fill")
                }
                .help("OpenAI / Claude / Gemini / Groq APIキーと PHP・Node.js 脆弱性監査MCP/スキルを設定します (⌘,)")

                Button(action: {
                    coordinator.webView?.evaluateJavaScript("openActionRequiredHubModal()", completionHandler: nil)
                }) {
                    Label("要対応一覧", systemImage: "exclamationmark.triangle.fill")
                }
                .help("全リポジトリの要対応アラート・理由・対策Diffを一覧表示します")

                Button(action: {
                    coordinator.webView?.evaluateJavaScript("openHealthModal()", completionHandler: nil)
                }) {
                    Label("死活監視", systemImage: "waveform.path.ecg")
                }
                .help("システム死活監視・疎通ステータスを確認します")

                Button(action: {
                    coordinator.webView?.reload()
                }) {
                    Label("再読み込み", systemImage: "arrow.clockwise")
                }
                .help("画面を再読み込みします (⌘R)")
            }
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let coordinator = WebViewCoordinator()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.appearance = NSAppearance(named: .darkAqua)
        NSApp.setActivationPolicy(.regular)
        if let iconPath = Bundle.main.path(forResource: "AppIcon", ofType: "icns"),
           let iconImg = NSImage(contentsOfFile: iconPath) {
            NSApp.applicationIconImage = iconImg
        }
        BackendServerManager.shared.startIfNeeded()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        BackendServerManager.shared.stop()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

@main
struct RepoChexApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup("RepoChex — Architecture & Vulnerability AI Studio") {
            MainContentView(coordinator: appDelegate.coordinator)
                .frame(minWidth: 1080, minHeight: 700)
                .preferredColorScheme(.dark)
        }
        .defaultSize(width: 1480, height: 920)
        .commands {
            TextEditingCommands()
            CommandGroup(replacing: .newItem) {
                Button("GitHub URLを追加分析 / リスト管理...") {
                    appDelegate.coordinator.webView?.evaluateJavaScript("openAnalyzeModal()", completionHandler: nil)
                }
                .keyboardShortcut("n", modifiers: [.command])

                Button("AI APIキー & 脆弱性監査設定 (管理画面)...") {
                    appDelegate.coordinator.webView?.evaluateJavaScript("openAdminSettingsModal()", completionHandler: nil)
                }
                .keyboardShortcut(",", modifiers: [.command])

                Button("要対応アラート一覧を表示") {
                    appDelegate.coordinator.webView?.evaluateJavaScript("openActionRequiredHubModal()", completionHandler: nil)
                }
                .keyboardShortcut("e", modifiers: [.command, .shift])

                Button("死活監視モニターを開く") {
                    appDelegate.coordinator.webView?.evaluateJavaScript("openHealthModal()", completionHandler: nil)
                }
                .keyboardShortcut("h", modifiers: [.command, .shift])
            }
        }
    }
}
