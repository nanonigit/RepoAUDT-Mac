"""Verify role contrast in the exact palette shipped to SwiftUI and WebKit."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PALETTES = json.loads((ROOT / 'Resources/webui/semantic-colors.json').read_text())


def luminance(hex_color):
    rgb = [int(hex_color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in rgb]
    return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))


def contrast(first, second):
    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


class PaletteTests(unittest.TestCase):
    def test_body_and_secondary_text(self):
        for theme, palette in PALETTES.items():
            for text in ('text', 'muted', 'actionText'):
                for background in ('background', 'surface', 'raised'):
                    with self.subTest(theme=theme, foreground=text, background=background):
                        self.assertGreaterEqual(contrast(palette[text], palette[background]), 4.5)

    def test_status_and_severity_labels(self):
        for theme, palette in PALETTES.items():
            for meaning in ('danger', 'warning', 'success', 'info'):
                for background in (meaning + 'Surface', 'surface', 'background'):
                    with self.subTest(theme=theme, role=meaning, background=background):
                        self.assertGreaterEqual(contrast(palette[meaning + 'Text'], palette[background]), 4.5)

    def test_primary_action_and_selection(self):
        for theme, palette in PALETTES.items():
            with self.subTest(theme=theme):
                self.assertGreaterEqual(contrast(palette['onAction'], palette['action']), 4.5)
                self.assertGreaterEqual(contrast(palette['text'], palette['selection']), 4.5)


if __name__ == '__main__':
    unittest.main()
