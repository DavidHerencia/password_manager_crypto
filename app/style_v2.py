# ---------------------------------------------------------
# 🌿 FRUTIGER AERO THEME — Glossy, Fresh, Round, Airy
# ---------------------------------------------------------
opcion = 3

if opcion == 1:
    # Dark theme — glossy aero night
    dark_bg = "#0f1020"
    dark_fg = "#1a1d33"
    dark_text = "#f0f8ff"
    dark_accent = "#66e4ff"       # aqua glossy
    dark_border = "#6eb3ff"
    dark_hover = "#27305a"
    dark_card_bg = "#14162b"
    dark_card_border = "#8cd1ff"
    dark_chip_text = "#0f1020"
    dark_soft = "#1c203a"

    # Light theme — refined soft blue
    light_bg = "#F2F5F9"
    light_fg = "#FFFFFF"
    light_text = "#1A1A1A"
    light_accent = "#4A8DE0"
    light_border = "#C9D7E6"
    light_hover = "#DCE7F5"
    light_card_bg = "#E7EDF5"
    light_card_border = "#8BB2E8"
    light_chip_text = "#FFFFFF"
    light_soft = "#EDF2F7"
elif opcion == 2:
    # Futuristic colors
    # Futuristic Dark — neon cyan & purple
    dark_bg = "#0D1117"
    dark_fg = "#161B22"
    dark_text = "#E6EEF7"
    dark_accent = "#00FFC8"        # neon cyan
    dark_border = "#303A46"
    dark_hover = "#1C2A30"
    dark_card_bg = "#1A222C"
    dark_card_border = "#8A4FFF"   # soft purple neon
    dark_chip_text = "#0D1117"
    dark_soft = "#141A21" 
    # Futuristic Light — aqua & lavender minimal
    light_bg = "#F6F9FC"
    light_fg = "#FFFFFF"
    light_text = "#1A1D21"
    light_accent = "#00B7A8"        # aqua futurista
    light_border = "#CBD5E1"
    light_hover = "#DFF6F3"
    light_card_bg = "#EDF1F7"
    light_card_border = "#A37CFF"   # lavender neon
    light_chip_text = "#FFFFFF"
    light_soft = "#EAF3FA"

else:
    # Colores: dark theme
    dark_bg = "#120d1c"
    dark_fg = "#241833"
    dark_text = "#f0e8ff"
    dark_accent = "#3df2ff" # letras
    dark_border = "#5f2df3"
    dark_hover = "#362448"
    dark_card_bg = "#201230"
    dark_card_border = "#ff6ac1"
    dark_chip_text = "#120d1c"
    dark_soft = "#1a1426"

    # Colores: light theme
    light_bg = "#fef6ff"
    light_fg = "#ffffff"
    light_text = "#1f1a2c"
    light_accent = "#ff5aa5" # letras
    light_border = "#ffd2f0"
    light_hover = "#ffe5fb"
    light_card_bg = "#fff0fb"
    light_card_border = "#ff7ad9"
    light_chip_text = "#ffffff"
    light_soft = "#f8e9ff"


def get_stylesheet(theme="dark"):
    if theme == "dark":
        bg, fg, text, accent, border, hover = dark_bg, dark_fg, dark_text, dark_accent, dark_border, dark_hover
        card_bg, card_border, chip_text, soft = dark_card_bg, dark_card_border, dark_chip_text, dark_soft
    else:
        bg, fg, text, accent, border, hover = light_bg, light_fg, light_text, light_accent, light_border, light_hover
        card_bg, card_border, chip_text, soft = light_card_bg, light_card_border, light_chip_text, light_soft

    return f"""
        QWidget {{
            background-color: {bg};
            color: {text};
            font-family: 'Segoe UI', 'JetBrains Mono', Arial;
            font-size: 14px;
        }}

        QMainWindow, QDialog {{
            background-color: {bg};
        }}

        QLabel {{
            color: {text};
        }}

        /* INPUTS — estilo aero, suaves y redondeados */
        QLineEdit {{
            background-color: rgba(255,255,255,0.06);
            border: 1.5px solid {border};
            border-radius: 14px;
            padding: 10px 14px;
            color: {text};
        }}
        QLineEdit:focus {{
            border-color: {accent};
            background-color: rgba(255,255,255,0.12);
        }}

        QLineEdit#searchBar {{
            border-radius: 22px;
            background-color: {soft};
            border: 1.5px solid {border};
            padding-left: 20px;
        }}

        #detailField, #detailPasswordField {{
            background-color: rgba(255,255,255,0.10);
            border: 2px solid transparent;
            border-radius: 20px;
            padding: 12px 16px;
            font-size: 15px;
        }}
        #detailField:focus, #detailPasswordField:focus {{
            border-color: {accent};
            background-color: rgba(255,255,255,0.16);
        }}

        /* BOTONES — estilo gel Frutiger Aero */
        QPushButton {{
            background: qlineargradient(
                x1:0, y1:0, x2:0, y2:1,
                stop:0 {accent},
                stop:1 {hover}
            );
            border: 2px solid {border};
            color: {bg};
            border-radius: 10px;
            padding: 10px 20px;
            font-weight: bold;
            letter-spacing: 0.3px;
        }}

        QPushButton:hover {{
            background: qlineargradient(
                x1:0, y1:0, x2:0, y2:1,
                stop:0 {hover},
                stop:1 {accent}
            );
            border-color: {accent};
        }}

        QPushButton#togglePassButton {{
            background-color: rgba(255,255,255,0.05);
            border: 2px solid {card_border};
            color: {card_border};
            border-radius: 18px;
            padding: 10px 20px;
            font-weight: bold;
        }}
        QPushButton#togglePassButton:hover {{
            background-color: {card_border};
            color: {chip_text};
        }}

        /* LISTA */
        QListWidget#vaultCardList {{
            background: transparent;
            border: none;
            padding: 0;
        }}

        QListWidget#vaultCardList::item {{
            margin-bottom: 14px;
            padding: 2px;
        }}

        QWidget#credentialCard {{
            background-color: {card_bg};
            border: 1.8px solid {card_border};
            border-radius: 24px;
            padding: 12px;
        }}
        QWidget#credentialCard:hover {{
            border-color: {accent};
            background-color: rgba(255,255,255,0.03);
        }}

        QLabel#cardBadge {{
            min-width: 42px;
            max-width: 42px;
            min-height: 42px;
            max-height: 42px;
            border-radius: 16px;
            background-color: {card_border};
            color: {chip_text};
            font-weight: bold;
            font-size: 18px;
        }}

        QLabel#cardChip {{
            padding: 3px 14px;
            border-radius: 999px;
            border: 1px solid {card_border};
            color: {card_border};
            font-size: 11px;
            letter-spacing: 3px;
        }}

        QLabel#cardPassword {{
            color: {accent};
            font-size: 18px;
            letter-spacing: 4px;
        }}

        /* SLIDERS */
        QSlider::groove:horizontal {{
            border: 1px solid {border};
            height: 8px;
            background: rgba(255,255,255,0.12);
            border-radius: 6px;
        }}

        QSlider::handle:horizontal {{
            background: {accent};
            border: 1px solid {accent};
            width: 20px;
            margin: -6px 0;
            border-radius: 10px;
        }}
    """
