import AppKit
import SwiftUI

/// A shared role palette for SwiftUI and the embedded audit surface.
enum SemanticColors {
    private static let palettes: [String: [String: String]] = {
        guard let root = Bundle.main.resourceURL,
              let data = try? Data(contentsOf: root.appendingPathComponent("webui/semantic-colors.json")),
              let values = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else {
            return [:]
        }
        return values
    }()

    static func role(_ name: String) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let theme = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? "dark" : "light"
            guard let hex = palettes[theme]?[name],
                  let rgb = UInt32(hex.dropFirst(), radix: 16) else { return .labelColor }
            return NSColor(srgbRed: CGFloat((rgb >> 16) & 255) / 255,
                           green: CGFloat((rgb >> 8) & 255) / 255,
                           blue: CGFloat(rgb & 255) / 255, alpha: 1)
        })
    }

    static func severityRole(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical", "high": return "danger"
        case "medium", "warning": return "warning"
        case "low", "info", "suggestion": return "info"
        default: return "neutral"
        }
    }

    static func severityColor(_ severity: String) -> Color {
        let meaning = severityRole(severity)
        return meaning == "neutral" ? role("muted") : role(meaning + "Text")
    }

    static func severitySymbol(_ severity: String) -> String {
        switch severityRole(severity) {
        case "danger": return "exclamationmark.octagon"
        case "warning": return "exclamationmark.triangle"
        case "info": return "info.circle"
        default: return "minus.circle"
        }
    }
}
