# Estilos QSS
# Colores: dark theme
dark_bg = "#1e1f22"
dark_fg = "#282a2e"
dark_text = "#dce0e5"
dark_accent = "#4195da" # letras
dark_border = "#3a3d43"
dark_hover = "#40434a"

# Colores: light theme
light_bg = "#fdfdfd"
light_fg = "#f2f2f2"
light_text = "#222222"
light_accent = "#007acc" # letras
light_border = "#dcdcdc"
light_hover = "#e8e8e8"


def get_stylesheet(theme="dark"):
    if theme == "dark":
        bg, fg, text, accent, border, hover = dark_bg, dark_fg, dark_text, dark_accent, dark_border, dark_hover
    else:
        bg, fg, text, accent, border, hover = light_bg, light_fg, light_text, light_accent, light_border, light_hover

    return f"""
        QWidget {{
            background-color: {bg};
            color: {text};
            font-family: Segoe UI, Arial;
            font-size: 14px;
        }}
        QMainWindow {{
            background-color: {bg};
        }}
        QDialog {{
            background-color: {bg};
        }}
        QLabel {{
            color: {text};
        }}
        QLineEdit {{
            background-color: {fg};
            border: 1px solid {border};
            border-radius: 5px;
            padding: 8px;
            color: {text};
        }}
        QLineEdit:focus {{
            border: 1px solid {accent};
        }}
        QPushButton {{
            background-color: {accent};
            color: white;
            border: none;
            border-radius: 5px;
            padding: 10px 15px;
        }}
        QPushButton:hover {{
            background-color: #82c0ff; /*azul mas claro para hover */
        }}
        QPushButton:pressed {{
            background-color: #529de0;
        }}
        QTableWidget {{
            background-color: {fg};
            border: 1px solid {border};
            gridline-color: {border};
            border-radius: 5px;
        }}
        QTableWidget::item {{
            padding: 5px;
        }}
        QTableWidget::item:selected {{
            background-color: {accent};
            color: white;
        }}
        QHeaderView::section {{
            background-color: {bg};
            color: {text};
            padding: 5px;
            border: 1px solid {border};
        }}
        QSlider::groove:horizontal {{
            border: 1px solid {border};
            height: 8px;
            background: {fg};
            margin: 2px 0;
            border-radius: 4px;
        }}
        QSlider::handle:horizontal {{
            background: {accent};
            border: 1px solid {accent};
            width: 18px;
            margin: -5px 0;
            border-radius: 9px;
        }}
    """
