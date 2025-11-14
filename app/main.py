import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QStackedWidget, QTableWidget,
    QTableWidgetItem, QAbstractItemView, QHeaderView, QDialog,
    QDialogButtonBox, QCheckBox, QSlider, QMessageBox
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QAction

# self modules
import crypto_engine
from crypto_engine import VAULT_EXISTS
from style import get_stylesheet

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
        self.service_input.setPlaceholderText("Nombre del Servicio (ej. Google)")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Usuario o Email")
        
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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Administrador de Contraseñas Seguro")
        self.setMinimumSize(800, 600)
        self.current_theme = "dark"

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
        file_menu = menu_bar.addMenu("Cerrar Sesion")
        lock_action = QAction("Bloquear", self)
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
        if not VAULT_EXISTS: 
            self.stacked_widget.setCurrentWidget(self.setup_page)
        else:
            self.stacked_widget.setCurrentWidget(self.login_page)

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
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
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
        
        create_button = QPushButton("Crear Bóveda")
        create_button.clicked.connect(self.handle_create_vault)
        
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
        
        layout.addWidget(container)
        return widget

    def _create_login_page(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        
        title = QLabel("Desbloquear Bóveda")
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)

        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("nombre de usuario")
        
        self.login_master_pass = QLineEdit()
        self.login_master_pass.setPlaceholderText("ingresa tu contraseña maestra")
        self.login_master_pass.setEchoMode(QLineEdit.Password)
        
        unlock_button = QPushButton("Desbloquear")
        unlock_button.clicked.connect(self.handle_unlock)
        
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
        
        layout.addWidget(container)
        return widget

    def _create_vault_page(self):
        widget = QWidget()
        main_layout = QHBoxLayout(widget)

        # Panel izquierdo (Lista de Entradas)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setFixedWidth(350)
        
        search_layout = QHBoxLayout()
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Buscar...")
        self.search_bar.textChanged.connect(self.filter_table)
        search_layout.addWidget(self.search_bar)
        
        self.entries_table = QTableWidget()
        self.entries_table.setColumnCount(2)
        self.entries_table.setHorizontalHeaderLabels(["Servicio", "Usuario"])
        self.entries_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.entries_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.entries_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.entries_table.itemSelectionChanged.connect(self.display_details)

        left_layout.addLayout(search_layout)
        left_layout.addWidget(self.entries_table)
        
        # Panel derecho (detalles y acciones)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        self.details_service = QLineEdit()
        self.details_service.setReadOnly(True)
        self.details_username = QLineEdit()
        self.details_username.setReadOnly(True)
        self.details_password = QLineEdit()
        self.details_password.setReadOnly(True)
        self.details_password.setEchoMode(QLineEdit.Password)

        # Botones de accion de detalles
        pass_actions_layout = QHBoxLayout()
        copy_user_btn = QPushButton("Copiar Usuario")
        copy_pass_btn = QPushButton("Copiar Contraseña")
        self.toggle_pass_btn = QPushButton("Mostrar")
        pass_actions_layout.addWidget(copy_user_btn)
        pass_actions_layout.addWidget(copy_pass_btn)
        pass_actions_layout.addWidget(self.toggle_pass_btn)
        self.toggle_pass_btn.clicked.connect(self.toggle_password_visibility)
        copy_user_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.details_username.text()))
        copy_pass_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.details_password.text()))

        # Botones de gestion de entradas
        entry_actions_layout = QHBoxLayout()
        add_btn = QPushButton("Añadir Nueva")
        edit_btn = QPushButton("Editar")
        delete_btn = QPushButton("Eliminar")
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
            return
        if not master_pass or master_pass != confirm_pass:
            QMessageBox.warning(self, "Error", "Las contraseñas no coinciden o están vacías.")
            return
        
        if crypto_engine.create_vault(username, master_pass):
            # Desbloquear automaticamente tras crear
            self.handle_unlock(username=username, password=master_pass)

    def handle_unlock(self):

        username = self.login_username.text()
        master_pass = self.login_master_pass.text()
        if not username or not master_pass:
            QMessageBox.warning(self, "Error", "El nombre de usuario y la contraseña maestra no pueden estar vacíos.")
            return

        # Este print es mucho más útil para depurar
        print(f"Desbloqueando... Usuario: '{username}', Contraseña: '{master_pass}'")
        data = crypto_engine.unlock_vault(username, master_pass)
        
        if data:
            self.vault_data = data
            self.populate_table()
            self.stacked_widget.setCurrentWidget(self.vault_page)
            self.login_master_pass.clear()
            self.login_username.clear() # Limpiar también el usuario
        else:
            QMessageBox.critical(self, "Error", "Usuario o Contraseña Maestra incorrecta.")
    
    def lock_vault(self):
        self.vault_data = {}
        self.clear_details()
        self.entries_table.setRowCount(0)
        self.stacked_widget.setCurrentWidget(self.login_page)

    def populate_table(self):
        self.entries_table.setRowCount(0)
        for entry_id, data in self.vault_data.items():
            row_position = self.entries_table.rowCount()
            self.entries_table.insertRow(row_position)
            self.entries_table.setItem(row_position, 0, QTableWidgetItem(data["service"]))
            self.entries_table.setItem(row_position, 1, QTableWidgetItem(data["username"]))
            # Guardamos el ID en la fila para facil acceso
            self.entries_table.item(row_position, 0).setData(Qt.UserRole, entry_id)

    def display_details(self):
        selected_items = self.entries_table.selectedItems()
        if not selected_items:
            self.clear_details()
            return
        
        entry_id = selected_items[0].data(Qt.UserRole)
        data = self.vault_data.get(entry_id)
        if data:
            self.details_service.setText(data["service"])
            self.details_username.setText(data["username"])
            self.details_password.setText(data["password"])
            self.details_password.setEchoMode(QLineEdit.Password)
            self.toggle_pass_btn.setText("Mostrar")

    def clear_details(self):
        self.details_service.clear()
        self.details_username.clear()
        self.details_password.clear()

    def toggle_password_visibility(self):
        if self.details_password.echoMode() == QLineEdit.Password:
            self.details_password.setEchoMode(QLineEdit.Normal)
            self.toggle_pass_btn.setText("Ocultar")
        else:
            self.details_password.setEchoMode(QLineEdit.Password)
            self.toggle_pass_btn.setText("Mostrar")
            
    def filter_table(self, text):
        for i in range(self.entries_table.rowCount()):
            service_item = self.entries_table.item(i, 0)
            username_item = self.entries_table.item(i, 1)
            match = text.lower() in service_item.text().lower() or \
                    text.lower() in username_item.text().lower()
            self.entries_table.setRowHidden(i, not match)

    def add_entry(self):
        dialog = AddEditDialog(parent=self)
        if dialog.exec():
            new_data = dialog.get_data()
            # TODO usar logica de crypto_engine para guardar y luego recargar
            crypto_engine.save_entry(new_data)
            QMessageBox.information(self, "exito", "Nueva credencial guardada.")
            # recargar datos, actualizar UI
            # self.vault_data = crypto_engine.unlock_vault(...)
            # self.populate_table()

    def edit_entry(self):
        selected_items = self.entries_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Seleccion", "Por favor, selecciona una credencial para editar.")
            return

        entry_id = selected_items[0].data(Qt.UserRole)
        entry_data = self.vault_data.get(entry_id)

        dialog = AddEditDialog(entry_data=entry_data, parent=self)
        if dialog.exec():
            updated_data = dialog.get_data()
            # TODO USAR LOGICA DE  crypto_engine para actualizar y luego recargar
            print(f"Actualizando ID {entry_id} con {updated_data}")
            QMessageBox.information(self, "exito", "Credencial actualizada.")
    
    def delete_entry(self):
        selected_items = self.entries_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Seleccion", "Por favor, selecciona una credencial para eliminar.")
            return

        entry_id = selected_items[0].data(Qt.UserRole)
        service_name = self.vault_data[entry_id]['service']
        
        reply = QMessageBox.question(self, 'Confirmar', 
                                     f"¿Estas seguro de que quieres eliminar la credencial para '{service_name}'?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            crypto_engine.delete_entry(entry_id)
            QMessageBox.information(self, "exito", "Credencial eliminada.")
            # Recargar y repoblar


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(get_stylesheet("dark")) # dark mode default 
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())