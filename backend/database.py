import sqlite3
import os
import json

# --- Configuración de la Base de Datos ---
DB_FILE = "vault.db"
DB_PATH = os.path.join(os.path.dirname(__file__), DB_FILE)

def get_db_connection():
    """Crea y retorna una conexión a la base de datos."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la base de datos y crea las tablas si no existen."""
    if os.path.exists(DB_PATH):
        return

    print(f"Creando nueva base de datos en: {DB_PATH}")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tabla para almacenar los usuarios y su información de autenticación
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            hash TEXT NOT NULL,
            salt_kdf TEXT NOT NULL
        );
    """)
    
    # Tabla para almacenar las bóvedas encriptadas
    cursor.execute("""
        CREATE TABLE vaults (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL UNIQUE,
            encrypted_blob TEXT NOT NULL,
            FOREIGN KEY (owner_username) REFERENCES users (username)
        );
    """)
    
    conn.commit()
    conn.close()
    print("Base de datos y tablas creadas con éxito.")

# --- Funciones de Usuario ---

def create_user(username: str, hashed_pass: str, salt_kdf: str) -> bool:
    """Crea un nuevo usuario en la tabla 'users'."""
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, hash, salt_kdf) VALUES (?, ?, ?)",
            (username, hashed_pass, salt_kdf)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user(username: str) -> dict | None:
    """Busca un usuario por su nombre. Retorna un diccionario o None."""
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

# --- Funciones de Bóveda ---

def get_vault(username: str) -> dict | None:
    """
    Busca una bóveda por el nombre de usuario del propietario.
    Retorna el blob encriptado (como dict) o None.
    """
    conn = get_db_connection()
    cursor = conn.execute("SELECT encrypted_blob FROM vaults WHERE owner_username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    
    if row and row["encrypted_blob"]:
        return json.loads(row["encrypted_blob"])
    return None

def update_or_create_vault(username: str, blob_data: dict) -> bool:
    """
    Actualiza una bóveda existente o la crea si no existe.
    El blob_data se guarda como un string JSON.
    """
    conn = get_db_connection()
    encrypted_blob_str = json.dumps(blob_data)
    
    try:
        # Intentar actualizar primero
        cursor = conn.execute(
            "UPDATE vaults SET encrypted_blob = ? WHERE owner_username = ?",
            (encrypted_blob_str, username)
        )
        
        if cursor.rowcount == 0:
            # Si no se actualizó ninguna fila, no existía, así que la insertamos
            conn.execute(
                "INSERT INTO vaults (owner_username, encrypted_blob) VALUES (?, ?)",
                (username, encrypted_blob_str)
            )
            
        conn.commit()
        return True
    except Exception as e:
        print(f"Error al actualizar/crear la bóveda: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

