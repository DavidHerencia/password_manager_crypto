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
    conn = get_db_connection()
    try:
        _ensure_users_table(conn)
        _ensure_vault_table(conn)
    finally:
        conn.close()

# --- Funciones de Usuario ---

def create_user(username: str, auth_hash: str, salt_kdf: str) -> bool:
    """Crea un nuevo usuario en la tabla 'users'."""
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, hash, salt_kdf) VALUES (?, ?, ?)",
            (username, auth_hash, salt_kdf)
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

def _table_exists(conn, table_name: str) -> bool:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    )
    return cursor.fetchone() is not None

def _ensure_users_table(conn):
    if _table_exists(conn, "users"):
        return
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            hash TEXT NOT NULL,
            salt_kdf TEXT NOT NULL
        );
    """)
    conn.commit()

def _create_vaults_table(conn):
    conn.execute("""
        CREATE TABLE vaults (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            tag TEXT NOT NULL,
            FOREIGN KEY (owner_username) REFERENCES users (username)
        );
    """)
    conn.commit()

def _ensure_vault_table(conn):
    if not _table_exists(conn, "vaults"):
        _create_vaults_table(conn)
        return
    cursor = conn.execute("PRAGMA table_info(vaults)")
    columns = {row[1] for row in cursor.fetchall()}
    required = {"salt", "nonce", "ciphertext", "tag"}
    if required.issubset(columns):
        return
    _migrate_vault_table(conn)

def _migrate_vault_table(conn):
    cursor = conn.cursor()
    cursor.execute("ALTER TABLE vaults RENAME TO vaults_old")
    _create_vaults_table(conn)
    cursor.execute("SELECT owner_username, encrypted_blob FROM vaults_old")
    rows = cursor.fetchall()
    inserted = 0
    for row in rows:
        owner = row[0]
        blob = row[1]
        if not blob:
            continue
        try:
            parsed = json.loads(blob)
        except json.JSONDecodeError:
            continue
        salt = parsed.get("salt")
        nonce = parsed.get("nonce")
        ciphertext = parsed.get("ciphertext")
        tag = parsed.get("tag")
        if not all((salt, nonce, ciphertext, tag)):
            continue
        cursor.execute(
            "INSERT INTO vaults (owner_username, salt, nonce, ciphertext, tag) VALUES (?, ?, ?, ?, ?)",
            (owner, salt, nonce, ciphertext, tag)
        )
        inserted += 1
    cursor.execute("DROP TABLE IF EXISTS vaults_old")
    conn.commit()

# --- Funciones de Bóveda ---

def get_vault(username: str) -> dict | None:
    conn = get_db_connection()
    cursor = conn.execute(
        "SELECT salt, nonce, ciphertext, tag FROM vaults WHERE owner_username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "salt": row["salt"],
        "nonce": row["nonce"],
        "ciphertext": row["ciphertext"],
        "tag": row["tag"],
    }

def update_or_create_vault(username: str, blob_data: dict) -> bool:
    """
    Actualiza una bóveda existente o la crea si no existe.
    El blob_data se guarda como un string JSON.
    """
    conn = get_db_connection()
    try:
        salt = blob_data["salt"]
        nonce = blob_data["nonce"]
        ciphertext = blob_data["ciphertext"]
        tag = blob_data["tag"]
    except KeyError as exc:
        print(f"Campo faltante al guardar vault: {exc}")
        conn.close()
        return False
    
    try:
        # Intentar actualizar primero
        cursor = conn.execute(
            "UPDATE vaults SET salt = ?, nonce = ?, ciphertext = ?, tag = ? WHERE owner_username = ?",
            (salt, nonce, ciphertext, tag, username)
        )
        
        if cursor.rowcount == 0:
            # Si no se actualizó ninguna fila, no existía, así que la insertamos
            conn.execute(
                "INSERT INTO vaults (owner_username, salt, nonce, ciphertext, tag) VALUES (?, ?, ?, ?, ?)",
                (username, salt, nonce, ciphertext, tag)
            )
            
        conn.commit()
        return True
    except Exception as e:
        print(f"Error al actualizar/crear la bóveda: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

