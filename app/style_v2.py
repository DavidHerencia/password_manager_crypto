# ---------------------------------------------------------
# Windows XP-inspired classic theme (high contrast + bevels)
# ---------------------------------------------------------

BASE_FONT = "'Tahoma', 'Segoe UI', Arial"

# Dark "midnight" variant
dark = {
    "bg": "#111a2d",
    "panel": "#1a2741",
    "panel_high": "#233554",
    "text": "#f8fbff",
    "muted": "#c7d0e6",
    "accent": "#2d6de1",
    "accent_alt": "#4b82f0",
    "border": "#0a1433",
    "header": "#142443",
    "selection": "#6fa0ff",
    "shadow": "#030814",
    "list_bg": "#0c1526",
    "card_base": "#1f2f4c",
    "card_alt": "#2e4675",
}

# Light "silver" variant
light = {
    "bg": "#dde6f7",
    "panel": "#edf2ff",
    "panel_high": "#ffffff",
    "text": "#112247",
    "muted": "#536182",
    "accent": "#1c57d6",
    "accent_alt": "#3a73f0",
    "border": "#9babc9",
    "header": "#cdd9ef",
    "selection": "#a6c4ff",
    "shadow": "#a0aec9",
    "list_bg": "#fefefe",
    "card_base": "#f8faff",
    "card_alt": "#dae5ff",
}

def _gradient(top_color: str, bottom_color: str) -> str:
    """Returns a vertical gradient expression for Qt stylesheets."""
    return (
        "qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 "
        f"{top_color}, stop:1 {bottom_color})"
    )

def get_stylesheet(theme: str = "dark") -> str:
    palette = dark if theme == "dark" else light
    bg = palette["bg"]
    panel = palette["panel"]
    panel_high = palette["panel_high"]
    text = palette["text"]
    muted = palette["muted"]
    accent = palette["accent"]
    accent_alt = palette["accent_alt"]
    border = palette["border"]
    header = palette["header"]
    selection = palette["selection"]
    shadow = palette["shadow"]
    list_bg = palette["list_bg"]
    card_base = palette["card_base"]
    card_alt = palette["card_alt"]

    button_grad = _gradient(panel_high, header)
    accent_grad = _gradient(accent_alt, accent)
    toolbar_grad = _gradient(header, panel)
    titlebar_grad = _gradient(accent, accent_alt)
    card_grad = _gradient(panel_high, panel)

    return f"""
        QWidget {{
            background-color: {bg};
            color: {text};
            font-family: {BASE_FONT};
            font-size: 13px;
        }}

        QMainWindow, QDialog {{
            background-color: {bg};
        }}

        QLabel {{
            color: {text};
        }}

        QLabel[accessibleName="muted"] {{
            color: {muted};
        }}

        QLabel#pageTitle {{
            padding: 0;
            margin-bottom: 0;
            border: none;
            padding: 4px 8px;
            border-bottom: 1px solid {border};
        }}

        QPushButton#linkButton {{
            background: transparent;
            border: none;
            color: {accent};
            text-align: left;
            padding: 0;
        }}

        QPushButton#linkButton:hover {{
            color: {accent_alt};
            text-decoration: underline;
            margin-bottom: 6px;
        }}

        QGroupBox, QWidget#panelBox {{
            background-color: {panel};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 10px;
        }}

        QLineEdit {{
            background-color: {panel_high};
            border: 1px solid {border};
            border-radius: 4px;
            padding: 6px 8px;
            color: {text};
        }}

        QLineEdit:focus {{
            border-color: {accent};
            outline: none;
            background-color: {panel};
        }}

        QLineEdit#searchBar {{
            background-color: {bg};
            border-radius: 18px;
            padding-left: 32px;
        }}

        QTextEdit, QPlainTextEdit {{
            background-color: {panel_high};
            border: 1px solid {border};
            border-radius: 4px;
            padding: 6px;
        }}

        QComboBox {{
            background-color: {panel_high};
            border: 1px solid {border};
            border-radius: 4px;
            padding: 4px 8px;
        }}

        QComboBox::drop-down {{
            width: 24px;
            border-left: 1px solid {border};
        }}

        QPushButton {{
            background: {button_grad};
            border: 1px solid {border};
            border-radius: 5px;
            padding: 6px 14px;
            color: {text};
            font-weight: 600;
            min-height: 28px;
        }}

        QPushButton:hover {{
            background: {accent_grad};
            border-color: {accent};
            color: #fefefe;
        }}

        QPushButton:pressed {{
            background: {accent};
            border-color: {accent};
            color: #fefefe;
        }}

        QPushButton:disabled {{
            color: {muted};
            background: {panel};
        }}

        QPushButton#togglePassButton {{
            background: {panel_high};
            color: {text};
        }}

        QListWidget {{
            background-color: {list_bg};
            border: 1px solid {border};
            border-radius: 8px;
            alternate-background-color: {panel_high};
            padding: 6px;
        }}

        QListWidget::item {{
            padding: 2px;
            margin-bottom: 8px;
            border-radius: 10px;
        }}

        QListWidget::item:selected {{
            background-color: {selection};
            color: #0b1634;
            border: 1px solid {accent};
            padding: 0;
        }}

        QWidget#credentialCard {{
            background: {card_base};
            border: 1px solid {border};
            border-radius: 8px;
            padding: 12px;
            border-left: 4px solid {border};
        }}

        QWidget#credentialCard[variant="base"] {{
            background: {card_base};
            border-color: {border};
            border-left-color: {border};
        }}

        QWidget#credentialCard[variant="base"] QLabel#cardBadge {{
            background: {button_grad};
        }}

        QWidget#credentialCard[variant="alt"] {{
            background: {card_alt};
            border-color: {accent};
            border-left-color: {accent_alt};
        }}

        QWidget#credentialCard[variant="alt"] QLabel#cardBadge {{
            background: {accent_grad};
        }}

        QWidget#credentialCard QLabel {{
            color: {text};
        }}

        QWidget#credentialCard:hover {{
            border-color: {accent};
        }}

        QLabel#cardBadge {{
            min-width: 28px;
            max-width: 28px;
            min-height: 28px;
            max-height: 28px;
            border-radius: 4px;
            background: {accent_grad};
            color: #fff;
            font-weight: bold;
            font-size: 13px;
            text-align: center;
        }}

        QLabel#cardIcon {{
            min-width: 24px;
            max-width: 24px;
            text-align: center;
            color: {muted};
            font-size: 16px;
        }}

        QLabel#cardService {{
            font-weight: 600;
            padding-right: 8px;
        }}

        QLabel#cardUsername {{
            color: {muted};
            padding-bottom: 2px;
        }}

        QLabel#cardPassword {{
            font-family: 'Consolas', 'Courier New', monospace;
            letter-spacing: 2px;
            color: {accent};
        }}

        QSlider::groove:horizontal {{
            background: {panel_high};
            border: 1px solid {border};
            height: 6px;
            border-radius: 3px;
        }}

        QSlider::handle:horizontal {{
            background: {accent};
            border: 1px solid {accent};
            width: 16px;
            margin: -5px 0;
            border-radius: 8px;
        }}

        QTabWidget::pane {{
            border: 1px solid {border};
            background: {panel};
            border-radius: 4px;
        }}

        QTabBar::tab {{
            background: {button_grad};
            border: 1px solid {border};
            padding: 6px 12px;
            margin-right: 2px;
        }}

        QTabBar::tab:selected {{
            background: {accent_grad};
            color: #fff;
        }}

        QProgressBar {{
            border: 1px solid {border};
            border-radius: 4px;
            background: {panel_high};
            text-align: center;
        }}

        QProgressBar::chunk {{
            background: {accent_grad};
        }}

        QProgressDialog {{
            background-color: {panel};
        }}

        QStatusBar {{
            background: {titlebar_grad};
            color: #ffffff;
            border-top: 2px solid {border};
            padding: 0 8px;
        }}

        QToolTip {{
            background-color: {panel_high};
            border: 1px solid {border};
            color: {text};
        }}

        QMenuBar {{
            background: {titlebar_grad};
            border-bottom: 2px solid {border};
        }}

        QMenuBar::item {{
            padding: 4px 12px;
        }}

        QMenuBar::item:selected {{
            background: #ffffff33;
            color: #fff;
        }}

        QToolBar {{
            background: {toolbar_grad};
            border-bottom: 1px solid {border};
        }}

        QScrollBar:vertical {{
            background: {panel};
            width: 14px;
            margin: 0;
            border: 1px solid {border};
        }}

        QScrollBar::handle:vertical {{
            background: {button_grad};
            min-height: 24px;
            border: 1px solid {border};
        }}

        QScrollBar::handle:vertical:hover {{
            background: {accent_grad};
        }}

        QScrollBar::up-arrow, QScrollBar::down-arrow {{
            border: none;
            width: 10px;
            height: 10px;
            background: transparent;
        }}
        
        QListWidget::item {{
            background: #edf2ff;
        }}
    """
