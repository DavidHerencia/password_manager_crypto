import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QStackedWidget, QListWidget,
    QListWidgetItem, QAbstractItemView, QDialog, QDialogButtonBox,
    QCheckBox, QSlider, QMessageBox, QProgressDialog, QStyle,
    QSizePolicy
)
from PySide6.QtCore import Qt, QRunnable, QThreadPool, QObject, Signal, Slot
from PySide6.QtGui import QAction

# self modules
import crypto_engine
from ui import get_stylesheet

class WorkerSignals(QObject):
    finished = Signal(object)
    error = Signal(str)


class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
            self.signals.finished.emit(result)
        except Exception as exc:
            self.signals.error.emit(str(exc))


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generador de Contraseñas")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        # Contraseña generada
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        layout.addWidget(self.password_display)

        # Longitud
        len_layout = QHBoxLayout()
        self.len_slider = QSlider(Qt.Horizontal)
        self.len_slider.setRange(8, 64)
        self.len_slider.setValue(16)
        self.len_label = QLabel("Longitud: 16")
        self.len_slider.valueChanged.connect(lambda v: self.len_label.setText(f"Longitud: {v}"))
        len_layout.addWidget(self.len_slider)
        len_layout.addWidget(self.len_label)
        layout.addLayout(len_layout)

        # Opciones
        self.chk_upper = QCheckBox("Mayusculas (A-Z)")
        self.chk_upper.setChecked(True)
        self.chk_numbers = QCheckBox("Numeros (0-9)")
        self.chk_numbers.setChecked(True)
        self.chk_symbols = QCheckBox("Simbolos (!@#$)")
        self.chk_symbols.setChecked(True)
        layout.addWidget(self.chk_upper)
        layout.addWidget(self.chk_numbers)
        layout.addWidget(self.chk_symbols)
        
        # Botones
        self.generate_button = QPushButton("Generar Nueva")
        self.generate_button.clicked.connect(self.generate)
        layout.addWidget(self.generate_button)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.generate()

    def generate(self):
        password = crypto_engine.generate_password(
            length=self.len_slider.value(),
            use_uppercase=self.chk_upper.isChecked(),
            use_numbers=self.chk_numbers.isChecked(),
            use_symbols=self.chk_symbols.isChecked()
        )
        self.password_display.setText(password)

    def get_password(self):
        return self.password_display.text()

class AddEditDialog(QDialog):
    def __init__(self, entry_data=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Añadir/Editar Credencial" if entry_data is None else "Editar Credencial")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Nombre del servicio (ej. Google)")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Usuario o email")
        
        pass_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Contraseña")
        self.password_input.setEchoMode(QLineEdit.Password)
        generate_btn = QPushButton("Generar")
        generate_btn.clicked.connect(self.open_generator)
        pass_layout.addWidget(self.password_input)
        pass_layout.addWidget(generate_btn)

        layout.addWidget(QLabel("Servicio:"))
        layout.addWidget(self.service_input)
        layout.addWidget(QLabel("Usuario:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Contraseña:"))
        layout.addLayout(pass_layout)

        if entry_data:
            self.service_input.setText(entry_data.get('service', ''))
            self.username_input.setText(entry_data.get('username', ''))
            self.password_input.setText(entry_data.get('password', ''))

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def open_generator(self):
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec():
            self.password_input.setText(dialog.get_password())

    def get_data(self):
        return {
            "service": self.service_input.text(),
            "username": self.username_input.text(),
            "password": self.password_input.text()
        }

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QSizePolicy
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

class CredentialCard(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("credentialCard")
        
        # --- Estados Internos ---
        self._is_selected = False
        self._is_hovered = False

        # --- Colores (se obtendrán del stylesheet) ---
        self._color_base_bg = ""
        self._color_hover_bg = ""
        self._color_selected_bg = ""
        self._color_base_border = ""
        self._color_hover_border = ""
        self._color_selected_border = ""

        # --- Configuración principal del Layout del Item ---
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(2, 2, 2, 2)
        
        self.container = QFrame()
        self.container.setObjectName("cardContainer")
        main_layout.addWidget(self.container)

        card_layout = QHBoxLayout(self.container)
        card_layout.setContentsMargins(8, 6, 8, 6)
        card_layout.setSpacing(10)

        self.badge_label = QLabel("?")
        self.badge_label.setObjectName("cardBadge")
        self.badge_label.setFixedSize(40, 40)
        self.badge_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.badge_label)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        info_layout.setContentsMargins(0, 0, 0, 0)
        
        self.service_label = QLabel()
        self.service_label.setObjectName("cardService")
        info_layout.addWidget(self.service_label)

        user_layout = QHBoxLayout()
        user_layout.setSpacing(4)
        self.username_icon = QLabel("👤")
        self.username_icon.setObjectName("cardIcon")
        self.username_label = QLabel()
        self.username_label.setObjectName("cardUsername")
        user_layout.addWidget(self.username_icon)
        user_layout.addWidget(self.username_label)
        user_layout.addStretch()
        info_layout.addLayout(user_layout)

        pass_layout = QHBoxLayout()
        pass_layout.setSpacing(4)
        self.password_icon = QLabel("🔑")
        self.password_icon.setObjectName("cardIcon")
        self.password_label = QLabel()
        self.password_label.setObjectName("cardPassword")
        pass_layout.addWidget(self.password_icon)
        pass_layout.addWidget(self.password_label)
        pass_layout.addStretch()
        info_layout.addLayout(pass_layout)

        card_layout.addLayout(info_layout, 1)
        self.setMinimumHeight(65)

        # Forzar la carga inicial de colores desde el stylesheet
        self.update_style_from_palette()

    def update_style_from_palette(self):
        """Carga los colores desde las propiedades del stylesheet para uso dinámico."""
        # Usamos valores fijos que coinciden con ui.py para evitar complejidad
        # de leer el stylesheet parseado.
        self._color_base_bg = "#f8faff"
        self._color_hover_bg = "#dae5ff"
        self._color_selected_bg = "#a6c4ff"
        self._color_base_border = "#9babc9"
        self._color_hover_border = "#1c57d6"
        self._color_selected_border = "#1c57d6"
        self._apply_style()

    def _apply_style(self):
        """Aplica el estilo al contenedor basado en los estados internos."""
        bg_color = self._color_base_bg
        border_color = self._color_base_border
        border_width = 2
        border_left_width = 2

        if self._is_selected:
            bg_color = self._color_selected_bg
            border_color = self._color_selected_border
            border_left_width = 5
        elif self._is_hovered:
            bg_color = self._color_hover_bg
            border_color = self._color_hover_border

        self.container.setStyleSheet(f"""
            #cardContainer {{
                background-color: {bg_color};
                border: {border_width}px solid {border_color};
                border-left: {border_left_width}px solid {border_color};
                border-radius: 10px;
            }}
        """)

    def set_selected(self, selected: bool):
        """Método público para cambiar el estado de selección desde fuera."""
        if self._is_selected != selected:
            self._is_selected = selected
            self._apply_style()

    def enterEvent(self, event):
        """El mouse ha entrado en el widget."""
        self._is_hovered = True
        self._apply_style()
        super().enterEvent(event)

    def leaveEvent(self, event):
        """El mouse ha salido del widget."""
        self._is_hovered = False
        self._apply_style()
        super().leaveEvent(event)

    def set_data(self, service, username, password):
        self.service_text = service
        self.username_text = username
        
        badge_char = service[:1].upper() if service else "?"
        self.badge_label.setText(badge_char)
        
        self.service_label.setText(service or "(Sin nombre)")
        self.username_label.setText(username or "---")
        
        masked_len = max(4, min(len(password), 12)) if password else 4
        mask = "•" * masked_len
        masked = " ".join(mask[i:i + 4] for i in range(0, len(mask), 4))
        self.password_label.setText(masked)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Adminer")
        self.setMinimumSize(800, 600)
        self.current_theme = "dark"
        self.statusBar().showMessage("Listo")
        self.loading_dialog = None
        self.thread_pool = QThreadPool()
        self._workers = []
        self._init_icons()

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        self.vault_data = {}

        self.init_ui()
        self.check_initial_state()

    def init_ui(self):
        # Crear las diferentes "paginas" o vistas de la aplicacion
        self.setup_page = self._create_setup_page()
        self.login_page = self._create_login_page()
        self.vault_page = self._create_vault_page()

        self.stacked_widget.addWidget(self.setup_page)
        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.vault_page)

        # --- Barra de Menu ---
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("Sesion")
        lock_action = QAction("Bloquear", self)
        lock_action.setIcon(self.icons["lock"])
        lock_action.triggered.connect(self.lock_vault)
        file_menu.addAction(lock_action)
        
        view_menu = menu_bar.addMenu("Tema")
        self.theme_action = QAction("Claro", self)
        self.theme_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(self.theme_action)

    def check_initial_state(self):
        # if crypto_engine.check_db_exists():
        #     self.stacked_widget.setCurrentWidget(self.login_page)
        # else:
        #     self.stacked_widget.setCurrentWidget(self.setup_page)
        # TO TEST 
        # Aquí se podría validar estado inicial del backend si es necesario.
        # else:
        #     self.stacked_widget.setCurrentWidget(self.login_page)
        self.stacked_widget.setCurrentWidget(self.login_page)
        
        # DEBUG: Auto-login con credenciales por defecto
        self.login_username.setText("admin")
        self.login_master_pass.setText("1234")
        # Descomenta la siguiente línea para auto-login automático:
        # self.handle_unlock("admin", "password123")

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.current_theme = "light"
            self.theme_action.setText("Oscuro")
        else:
            self.current_theme = "dark"
            self.theme_action.setText("Claro")
        QApplication.instance().setStyleSheet(get_stylesheet(self.current_theme))

    # Paginas de la UI
    def _create_setup_page(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        
        title = QLabel("Crear Bóveda Segura")
        title.setObjectName("pageTitle")
        title.setAlignment(Qt.AlignCenter)

        # Create user
        self.setup_username = QLineEdit()
        self.setup_username.setPlaceholderText("nombre de usuario")
        
        self.setup_master_pass = QLineEdit()
        self.setup_master_pass.setPlaceholderText("contraseña maestra fuerte")
        self.setup_master_pass.setEchoMode(QLineEdit.Password)
        
        self.setup_confirm_pass = QLineEdit()
        self.setup_confirm_pass.setPlaceholderText("confirma tu contraseña maestra")
        self.setup_confirm_pass.setEchoMode(QLineEdit.Password)
        
        #WARNING
        self.warning_label = QLabel("⚠️ Tu contraseña maestra no puede recuperarse. Si la olvidas, perderás acceso a la bóveda.")
        self.warning_label.setWordWrap(True)
        self.warning_label.setAccessibleName("muted")

        create_button =  QPushButton("Crear Bóveda")
        create_button.clicked.connect(self.handle_create_vault)

        login_button = QPushButton("¿Ya tienes una bóveda? Iniciar Sesión")
        login_button.setObjectName("linkButton")
        login_button.setCursor(Qt.PointingHandCursor)
        login_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.login_page))
        
        
        container = QWidget()
        container.setFixedWidth(400)
        container_layout = QVBoxLayout(container)
        container_layout.addWidget(title)
        container_layout.addSpacing(20)
        container_layout.addWidget(QLabel("Nombre de usuario:"))
        container_layout.addWidget(self.setup_username)
        container_layout.addWidget(QLabel("Contraseña maestra:"))
        container_layout.addWidget(self.setup_master_pass)
        container_layout.addWidget(QLabel("Confirmar contraseña:"))
        container_layout.addWidget(self.setup_confirm_pass)
        container_layout.addSpacing(10)
        container_layout.addWidget(create_button)
        container_layout.addSpacing(10)
        container_layout.addWidget(login_button)
        container_layout.addSpacing(20)
        container_layout.addWidget(self.warning_label)
        
        layout.addWidget(container)
        return widget

    def _create_login_page(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        
        title = QLabel("Desbloquear Bóveda")
        title.setObjectName("pageTitle")
        title.setAlignment(Qt.AlignCenter)

        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("nombre de usuario")
        
        self.login_master_pass = QLineEdit()
        self.login_master_pass.setPlaceholderText("ingresa tu contraseña maestra")
        self.login_master_pass.setEchoMode(QLineEdit.Password)
        
        unlock_button = QPushButton("Desbloquear")
        unlock_button.clicked.connect(self.handle_unlock)

        setup_button = QPushButton("¿No tienes bóveda? Crear una")
        setup_button.setObjectName("linkButton")
        setup_button.setCursor(Qt.PointingHandCursor)
        setup_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.setup_page))     
        
        container = QWidget()
        container.setFixedWidth(400)
        container_layout = QVBoxLayout(container)
        container_layout.addWidget(title)
        container_layout.addSpacing(20)
        container_layout.addWidget(QLabel("Nombre de usuario:"))
        container_layout.addWidget(self.login_username)
        container_layout.addWidget(QLabel("Contraseña maestra:"))
        container_layout.addWidget(self.login_master_pass)
        container_layout.addSpacing(10)
        container_layout.addWidget(unlock_button)
        container_layout.addSpacing(10)
        container_layout.addWidget(setup_button)
        
        layout.addWidget(container)
        return widget

    def _create_vault_page(self):
        widget = QWidget()
        main_layout = QHBoxLayout(widget)

        # Panel izquierdo (Lista de Entradas)
        left_panel = QWidget()
        left_panel.setObjectName("leftPanel")
        left_layout = QVBoxLayout(left_panel)
        left_panel.setFixedWidth(370)
        
        search_layout = QHBoxLayout()
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Buscar servicio o usuario...")
        self.search_bar.setClearButtonEnabled(True)
        self.search_bar.setObjectName("searchBar")
        self.search_bar.textChanged.connect(self.filter_table)
        search_layout.addWidget(self.search_bar)
        
        self.entries_list = QListWidget()
        self.entries_list.setObjectName("vaultCardList")
        self.entries_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.entries_list.setSpacing(2)
        self.entries_list.setUniformItemSizes(False)
        self.entries_list.itemSelectionChanged.connect(self.on_selection_changed)

        left_layout.addLayout(search_layout)
        left_layout.addWidget(self.entries_list)
        
        # Panel derecho (detalles y acciones)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setSpacing(12)
        
        self.details_service = QLineEdit()
        self.details_service.setReadOnly(True)
        self.details_service.setObjectName("detailField")
        self.details_username = QLineEdit()
        self.details_username.setReadOnly(True)
        self.details_username.setObjectName("detailField")
        self.details_password = QLineEdit()
        self.details_password.setReadOnly(True)
        self.details_password.setEchoMode(QLineEdit.Password)
        self.details_password.setObjectName("detailPasswordField")

        # Botones de accion de detalles
        pass_actions_layout = QHBoxLayout()
        copy_user_btn = QPushButton("Copiar usuario")
        copy_user_btn.setIcon(self.icons["copy_user"])
        copy_pass_btn = QPushButton("Copiar contraseña")
        copy_pass_btn.setIcon(self.icons["copy_pass"])
        self.toggle_pass_btn = QPushButton("Mostrar")
        self.toggle_pass_btn.setObjectName("togglePassButton")
        self._update_password_toggle(False)
        pass_actions_layout.addWidget(copy_user_btn)
        pass_actions_layout.addWidget(copy_pass_btn)
        pass_actions_layout.addWidget(self.toggle_pass_btn)
        self.toggle_pass_btn.clicked.connect(self.toggle_password_visibility)
        copy_user_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.details_username.text()))
        copy_pass_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.details_password.text()))

        # Botones de gestion de entradas
        entry_actions_layout = QHBoxLayout()
        add_btn = QPushButton("Añadir Nueva")
        add_btn.setIcon(self.icons["add_entry"])
        edit_btn = QPushButton("Editar")
        edit_btn.setIcon(self.icons["edit_entry"])
        delete_btn = QPushButton("Eliminar")
        delete_btn.setIcon(self.icons["delete_entry"])
        entry_actions_layout.addWidget(add_btn)
        entry_actions_layout.addWidget(edit_btn)
        entry_actions_layout.addWidget(delete_btn)
        add_btn.clicked.connect(self.add_entry)
        edit_btn.clicked.connect(self.edit_entry)
        delete_btn.clicked.connect(self.delete_entry)
        
        right_layout.addWidget(QLabel("Servicio:"))
        right_layout.addWidget(self.details_service)
        right_layout.addWidget(QLabel("Usuario:"))
        right_layout.addWidget(self.details_username)
        right_layout.addWidget(QLabel("Contraseña:"))
        right_layout.addWidget(self.details_password)
        right_layout.addLayout(pass_actions_layout)
        right_layout.addStretch()
        right_layout.addLayout(entry_actions_layout)

        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)
        return widget

    # Logica de handlers
    def handle_create_vault(self):
        username = self.setup_username.text()
        master_pass = self.setup_master_pass.text()
        confirm_pass = self.setup_confirm_pass.text()
        if not username:
            QMessageBox.warning(self, "Error", "El nombre de usuario no puede estar vacío.")
            self.statusBar().showMessage("Nombre de usuario vacío.", 5000)
            return
        if not master_pass or master_pass != confirm_pass:
            QMessageBox.warning(self, "Error", "Las contraseñas no coinciden o están vacías.")
            self.statusBar().showMessage("Las contraseñas no coinciden.", 5000)
            return
        
        self.show_loading("Creando bóveda...")

        def on_success(result):
            self.hide_loading()
            if result is not None:
                self._apply_vault_data(result)
                self.statusBar().showMessage("Bóveda creada y sincronizada.", 5000)
            else:
                QMessageBox.critical(self, "Error", "No se pudo crear la bóveda. Intenta nuevamente.")
                self.statusBar().showMessage("Fallo al crear la bóveda.", 5000)

        self.run_backend_task(
            crypto_engine.create_vault,
            on_success,
            lambda err: self._handle_backend_error(err, "crear la bóveda"),
            username,
            master_pass
        )

    def handle_unlock(self, username=None, password=None):

        username = username or self.login_username.text()
        master_pass = password or self.login_master_pass.text()
        if not username or not master_pass:
            QMessageBox.warning(self, "Error", "El nombre de usuario y la contraseña maestra no pueden estar vacíos.")
            self.statusBar().showMessage("Credenciales incompletas.", 5000)
            return

        # Este print es mucho más útil para depurar
        print(f"Desbloqueando... Usuario: '{username}', Contraseña: '{master_pass}'")
        self.show_loading("Sincronizando bóveda...")

        def on_success(data):
            self.hide_loading()
            if data is not None:
                self._apply_vault_data(data)
                self.statusBar().showMessage("Bóveda sincronizada correctamente.", 5000)
            else:
                QMessageBox.critical(self, "Error", "Usuario o Contraseña Maestra incorrecta.")
                self.statusBar().showMessage("No se pudo desbloquear la bóveda.", 5000)

        self.run_backend_task(
            crypto_engine.unlock_vault,
            on_success,
            lambda err: self._handle_backend_error(err, "desbloquear la bóveda"),
            username,
            master_pass
        )

    def show_loading(self, message):
        if self.loading_dialog is None:
            self.loading_dialog = QProgressDialog(message, None, 0, 0, self)
            self.loading_dialog.setWindowTitle("Por favor espera")
            self.loading_dialog.setWindowModality(Qt.ApplicationModal)
            self.loading_dialog.setCancelButton(None)
            self.loading_dialog.setMinimumDuration(0)
        self.loading_dialog.setLabelText(message)
        self.loading_dialog.show()
        QApplication.processEvents()

    def hide_loading(self):
        if self.loading_dialog:
            self.loading_dialog.hide()

    def run_backend_task(self, func, on_success, on_error, *args, **kwargs):
        worker = Worker(func, *args, **kwargs)
        self._workers.append(worker)

        def cleanup(*_):
            if worker in self._workers:
                self._workers.remove(worker)

        def handle_success(result):
            cleanup()
            on_success(result)

        def handle_error(message):
            cleanup()
            on_error(message)

        worker.signals.finished.connect(handle_success)
        worker.signals.error.connect(handle_error)
        self.thread_pool.start(worker)

    def _apply_vault_data(self, data):
        self.vault_data = data
        self.populate_table()
        self.stacked_widget.setCurrentWidget(self.vault_page)
        self.login_master_pass.clear()
        self.login_username.clear()

    def _handle_backend_error(self, message, context):
        self.hide_loading()
        QMessageBox.critical(
            self,
            "Error",
            f"No se pudo {context}.\nDetalle: {message}"
        )
        self.statusBar().showMessage("Error en la operación.", 5000)
    
    def lock_vault(self):
        self.vault_data = {}
        self.clear_details()
        self.entries_list.clear()
        self.stacked_widget.setCurrentWidget(self.login_page)

    def populate_table(self):
        self.entries_list.clear()
        for index, (entry_id, data) in enumerate(self.vault_data.items()):
            item = QListWidgetItem()
            card = CredentialCard()
            card.set_data(data["service"], data["username"], data["password"])
            item.setSizeHint(card.sizeHint())
            item.setData(Qt.UserRole, entry_id)
            self.entries_list.addItem(item)
            self.entries_list.setItemWidget(item, card)
        if self.entries_list.count() > 0:
            self.entries_list.setCurrentRow(0)
        self.on_selection_changed()

    def on_selection_changed(self):
        """Gestiona el cambio de selección en la lista."""
        selected_items = self.entries_list.selectedItems()
        selected_id = None
        if selected_items:
            selected_id = selected_items[0].data(Qt.UserRole)

        # Actualizar el estado visual de todas las tarjetas
        for i in range(self.entries_list.count()):
            item = self.entries_list.item(i)
            card = self.entries_list.itemWidget(item)
            if card:
                entry_id = item.data(Qt.UserRole)
                card.set_selected(entry_id == selected_id)
        
        # Mostrar detalles del elemento seleccionado
        self.display_details()

    def display_details(self):
        current_item = self.entries_list.currentItem()
        if current_item is None:
            self.clear_details()
            return
        
        entry_id = current_item.data(Qt.UserRole)
        data = self.vault_data.get(entry_id)
        if data:
            self.details_service.setText(data["service"])
            self.details_username.setText(data["username"])
            self.details_password.setText(data["password"])
            self.details_password.setEchoMode(QLineEdit.Password)
            self._update_password_toggle(False)

    def clear_details(self):
        self.details_service.clear()
        self.details_username.clear()
        self.details_password.clear()
        self._update_password_toggle(False)
        if hasattr(self, "entries_list"):
            block_state = self.entries_list.blockSignals(True)
            self.entries_list.clearSelection()
            self.entries_list.blockSignals(block_state)

    def toggle_password_visibility(self):
        if self.details_password.echoMode() == QLineEdit.Password:
            self.details_password.setEchoMode(QLineEdit.Normal)
            self._update_password_toggle(True)
        else:
            self.details_password.setEchoMode(QLineEdit.Password)
            self._update_password_toggle(False)

    def _init_icons(self):
        style = self.style()
        self.icons = {
            "copy_user": style.standardIcon(QStyle.SP_DialogOpenButton),
            "copy_pass": style.standardIcon(QStyle.SP_DialogSaveButton),
            "show_password": style.standardIcon(QStyle.SP_DialogYesButton),
            "hide_password": style.standardIcon(QStyle.SP_DialogNoButton),
            "add_entry": style.standardIcon(QStyle.SP_FileDialogNewFolder),
            "edit_entry": style.standardIcon(QStyle.SP_FileDialogDetailedView),
            "delete_entry": style.standardIcon(QStyle.SP_TrashIcon),
            "lock": style.standardIcon(QStyle.SP_DialogCloseButton),
        }

    def _update_password_toggle(self, revealing: bool):
        if not hasattr(self, "toggle_pass_btn"):
            return
        if revealing:
            self.toggle_pass_btn.setText("Ocultar")
            self.toggle_pass_btn.setIcon(self.icons["hide_password"])
        else:
            self.toggle_pass_btn.setText("Mostrar")
            self.toggle_pass_btn.setIcon(self.icons["show_password"])
            
    def filter_table(self, text):
        text_lower = text.lower()
        for i in range(self.entries_list.count()):
            item = self.entries_list.item(i)
            entry_id = item.data(Qt.UserRole)
            entry = self.vault_data.get(entry_id, {})
            service_val = entry.get("service", "")
            username_val = entry.get("username", "")
            match = text_lower in service_val.lower() or text_lower in username_val.lower()
            item.setHidden(not match)

    def add_entry(self):
        dialog = AddEditDialog(parent=self)
        if dialog.exec():
            new_data = dialog.get_data()
            self.show_loading("Guardando credencial...")

            def on_success(data):
                self.hide_loading()
                if data is not None:
                    self._apply_vault_data(data)
                    QMessageBox.information(self, "Éxito", "Nueva credencial guardada.")
                    self.statusBar().showMessage("Credencial guardada.", 4000)

            self.run_backend_task(
                crypto_engine.save_entry,
                on_success,
                lambda err: self._handle_backend_error(err, "guardar la credencial"),
                new_data
            )

    def edit_entry(self):
        current_item = self.entries_list.currentItem()
        if current_item is None:
            QMessageBox.warning(self, "Seleccion", "Por favor, selecciona una credencial para editar.")
            return

        entry_id = current_item.data(Qt.UserRole)
        entry_data = self.vault_data.get(entry_id)

        dialog = AddEditDialog(entry_data=entry_data, parent=self)
        if dialog.exec():
            updated_data = dialog.get_data()
            self.show_loading("Actualizando credencial...")

            def on_success(data):
                self.hide_loading()
                if data is not None:
                    self._apply_vault_data(data)
                    QMessageBox.information(self, "Éxito", "Credencial actualizada.")
                    self.statusBar().showMessage("Credencial actualizada.", 4000)

            self.run_backend_task(
                crypto_engine.save_entry,
                on_success,
                lambda err: self._handle_backend_error(err, "actualizar la credencial"),
                updated_data,
                entry_id=entry_id
            )
    
    def delete_entry(self):
        current_item = self.entries_list.currentItem()
        if current_item is None:
            QMessageBox.warning(self, "Seleccion", "Por favor, selecciona una credencial para eliminar.")
            return

        entry_id = current_item.data(Qt.UserRole)
        service_name = self.vault_data[entry_id]['service']
        
        reply = QMessageBox.question(self, 'Confirmar', 
                                     f"¿Estas seguro de que quieres eliminar la credencial para '{service_name}'?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.show_loading("Eliminando credencial...")

            def on_success(data):
                self.hide_loading()
                if data is not None:
                    self._apply_vault_data(data)
                    QMessageBox.information(self, "Éxito", "Credencial eliminada.")
                    self.statusBar().showMessage("Credencial eliminada.", 4000)

            self.run_backend_task(
                crypto_engine.delete_entry,
                on_success,
                lambda err: self._handle_backend_error(err, "eliminar la credencial"),
                entry_id
            )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(get_stylesheet()) # dark mode default 
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())