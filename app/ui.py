
# ---------------------------------------------------------
# Tema claro por defecto (sin soporte para temas)
# ---------------------------------------------------------

BASE_FONT = "'Tahoma', 'Segoe UI', Arial"

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

def get_stylesheet() -> str:
    palette = light
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
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f0f4ff, stop:1 #e8ecff);
            border: 1px solid {border};
            border-radius: 12px;
            outline: none;
            padding: 8px;
        }}

        QListWidget::item {{
            background: transparent;
            border: none;
            padding: 0px;
            margin: 0px;
        }}

        QListWidget::item:selected {{
            background: transparent;
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
            background: #f0f4ff;
            width: 18px;
            margin: 0;
            border: none;
        }}

        QScrollBar::handle:vertical {{
            background: {accent};
            min-height: 24px;
            border: none;
            border-radius: 9px;
            margin: 2px;
        }}

        QScrollBar::handle:vertical:hover {{
            background: {accent_alt};
            width: 20px;
        }}

        QScrollBar::sub-line:vertical, QScrollBar::add-line:vertical {{
            border: none;
            background: none;
        }}

        QScrollBar::up-arrow, QScrollBar::down-arrow {{
            border: none;
            width: 10px;
            height: 10px;
            background: transparent;
        }}

        /* El contenedor real de la tarjeta - ESTILO BASE */
        #cardContainer {{
            background-color: {card_base};
            border: 2px solid {border};
            border-radius: 10px;
            padding: 12px;
            margin: 1px 0px;
            border-bottom: 3px solid {shadow};
        }}

        /* Panel lateral izquierdo */
        #leftPanel {{
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f5f8ff, stop:1 #eef2ff);
            border-right: 2px solid {border};
        }}

        /* El Badge Circular */
        #cardBadge {{
            background-color: {accent_alt};
            color: white;
            border-radius: 20px; /* La mitad del tamaño fijo (40px) para hacerlo círculo */
            font-weight: bold;
            font-size: 18px;
        }}

        /* Título del servicio */
        #cardService {{
            font-weight: bold;
            font-size: 14px;
            color: {text};
        }}

        /* Usuario y Password (más sutiles) */
        #cardUsername, #cardPassword {{
            font-size: 12px;
            color: {muted};
        }}

        /* Iconos pequeños */
        #cardIcon {{
            font-size: 10px;
            color: {muted};
            background: transparent;
        }}
    """
