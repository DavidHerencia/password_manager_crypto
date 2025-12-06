#TODO LOGIC GEN, ENCK Y DECK

# --- Real backend logic ---

import random
import string
import secrets
import requests
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import os
import json
import hashlib
from pathlib import Path

# Carpeta local para almacenar secretos del cliente (pepper y salt)
CONFIG_DIR = Path.home() / ".password_manager_crypto"
VAULT_SALT_LENGTH = 32  # bytes generados por cifrado del vault

BACKEND_URL = "http://localhost:8000"  # Cambia si tu backend está en otro host/puerto
ph = PasswordHasher()
session = requests.Session()
token = None

# Salt almacenado por usuario (bytes)
last_salt = None

# Vault cache en memoria (dict)
vault_data = {}
master_key = None
username_cache = None

_client_secrets_cache: dict[str, dict[str, str | None]] = {}
_client_secrets_recently_created: dict[str, bool] = {}


def _normalize_username(username: str) -> str:
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Se requiere un nombre de usuario no vacío para administrar secretos locales")
    return username.strip().lower()


def _secrets_file_for(username: str) -> Path:
    normalized = _normalize_username(username)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return CONFIG_DIR / f"{digest}.json"


def _write_client_secrets(normalized: str, payload: dict[str, str | None]) -> None:
    secrets_file = _secrets_file_for(normalized)
    with secrets_file.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    if os.name != "nt":
        os.chmod(secrets_file, 0o600)
    _client_secrets_cache[normalized] = payload


def _load_or_create_client_secrets(username: str) -> dict[str, str | None]:
    """Obtiene (o genera) el pepper y el salt local para un usuario concreto."""
    global _client_secrets_cache, _client_secrets_recently_created

    normalized = _normalize_username(username)

    if normalized in _client_secrets_cache:
        return _client_secrets_cache[normalized]

    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            CONFIG_DIR.chmod(0o700)
    except Exception as exc:
        raise RuntimeError("No se pudo preparar la carpeta de configuración local") from exc

    secrets_file = _secrets_file_for(normalized)

    if secrets_file.exists():
        try:
            with secrets_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            raise RuntimeError("No se pudo leer el archivo de secretos del cliente") from exc

        if not isinstance(data, dict) or "pepper" not in data:
            raise RuntimeError("El archivo de secretos del cliente no tiene el formato esperado")

        # Migración de formatos anteriores: client_salt / vault_salt -> salt único
        salt_hex = data.get("salt") or data.get("vault_salt") or data.get("client_salt")
        normalized_payload = {
            "pepper": data["pepper"],
            "salt": salt_hex
        }

        _write_client_secrets(normalized, normalized_payload)
        _client_secrets_cache[normalized] = normalized_payload
        _client_secrets_recently_created[normalized] = False
        return normalized_payload

    #en caso que no exista el archivo, crear nuevos secretos
    secrets_payload = {
        "pepper": secrets.token_hex(32),
        "salt": None
    }

    _write_client_secrets(normalized, secrets_payload)
    _client_secrets_recently_created[normalized] = True
    return secrets_payload


def get_local_secret_material(username: str, reset_flag: bool = True) -> dict[str, str | bool]:
    """Retorna pepper/salt locales y si fueron creados en esta sesión."""
    normalized = _normalize_username(username)

    secrets_payload = _load_or_create_client_secrets(normalized)
    generated_now = _client_secrets_recently_created.get(normalized, False)
    if reset_flag:
        _client_secrets_recently_created[normalized] = False
    return {
        "pepper": secrets_payload["pepper"],
        "salt": secrets_payload.get("salt"),
        "generated_now": generated_now,
        "config_path": str(_secrets_file_for(normalized))
    }

def set_token(jwt):
    global token
    token = jwt
    session.headers.update({"Authorization": f"Bearer {jwt}"})

def derive_key(password: str, salt: bytes, username: str, local_salt: bytes | None = None) -> bytes:
    from argon2.low_level import hash_secret_raw, Type
    secrets_payload = _load_or_create_client_secrets(username)
    pepper_bytes = bytes.fromhex(secrets_payload["pepper"])
    
    # Si tenemos salt local, verificamos que el servidor no lo haya alterado
    if local_salt is not None and local_salt != salt:
        raise RuntimeError(
            f"🚨 TAMPERING DETECTED: Salt mismatch!\n"
            f"   Local salt:  {local_salt.hex()}\n"
            f"   Server salt: {salt.hex()}\n"
            f"   Database data may be compromised. Aborting decryption."
        )
    
    secret = password.encode("utf-8") + pepper_bytes
    return hash_secret_raw(
        secret, salt,
        time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID
    )

def encrypt_vault(vault_dict, password, salt: bytes | None = None, username: str | None = None):
    """Serializa y cifra el vault dict con un salt nuevo si no se provee."""
    if username is None:
        raise RuntimeError("Se requiere un nombre de usuario para cifrar la bóveda")
    
    salt_bytes = salt if salt is not None else os.urandom(VAULT_SALT_LENGTH)
    key = derive_key(password, salt_bytes, username)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    data = json.dumps(vault_dict).encode()
    ct = aesgcm.encrypt(nonce, data, None)
    
    ciphertext, tag = ct[:-16], ct[-16:]
    return {
        "salt": salt_bytes.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }
def _update_client_salt(username: str, salt_hex: str | None) -> None:
    normalized = _normalize_username(username)
    secrets_payload = dict(_load_or_create_client_secrets(normalized))
    if secrets_payload.get("salt") == salt_hex:
        return
    secrets_payload["salt"] = salt_hex
    _write_client_secrets(normalized, secrets_payload)


def decrypt_vault(blob, password, username: str | None = None):
    try:
        salt_hex = blob["salt"]
        nonce_hex = blob["nonce"]
        ciphertext_hex = blob["ciphertext"]
        tag_hex = blob["tag"]
    except KeyError as exc:
        print(f"Campos faltantes en el blob cifrado: {exc}")
        return {"error": "MALFORMED_DATA", "message": "Vault data is corrupted"}

    try:
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
    except ValueError as exc:
        print(f"Formato inválido en el blob cifrado (no es hexadecimal válido): {exc}")
        print(f"  salt_hex: {salt_hex}")
        print(f"  nonce_hex: {nonce_hex}")
        return {"error": "MALFORMED_DATA", "message": "Vault data is corrupted"}

    ct = ciphertext + tag

    try:
        if username is None:
            raise RuntimeError("Se requiere un nombre de usuario para descifrar la bóveda")
        
        # Obtener el salt local almacenado para verificar tampering ANTES de descifrar
        secrets_payload = _load_or_create_client_secrets(username)
        local_salt_hex = secrets_payload.get("salt")
        local_salt = bytes.fromhex(local_salt_hex) if local_salt_hex else None
        
        # Verificación explícita de tampering del salt
        if local_salt is not None and local_salt != salt:
            return {
                "error": "TAMPERING_DETECTED",
                "message": "CRITICAL: Vault integrity compromised. Salt mismatch detected.",
                "details": f"Local: {local_salt.hex()[:16]}... vs Server: {salt.hex()[:16]}..."
            }
        
        # Derivar clave pasando ambos salts para detección de tampering
        key = derive_key(password, salt, username, local_salt=local_salt)
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(nonce, ct, None)
        print(f"✓ Vault decrypted successfully. Salt integrity verified.")
        return json.loads(data.decode())
    except RuntimeError as e:
        if "TAMPERING DETECTED" in str(e) or "SALT MISMATCH" in str(e):
            print(f"{e}")
            return {
                "error": "TAMPERING_DETECTED",
                "message": "CRITICAL: Vault integrity compromised. Salt mismatch detected."
            }
        raise
    except Exception as e:
        error_str = str(e)
        # Detectar si fue error de autenticación GCM (contraseña incorrecta o datos alterados)
        if "authentication tag did not verify" in error_str.lower() or "decrypt" in error_str.lower():
            return {
                "error": "AUTH_FAILED",
                "message": "Invalid password or vault data corrupted"
            }
        print(f"Error descifrando vault con secretos locales: {e}")
        return {"error": "DECRYPT_ERROR", "message": str(e)}
    
def create_vault(username, auth_password, master_password):
    global vault_data, master_key, username_cache, last_salt
    try:
        resp = session.post(
            f"{BACKEND_URL}/api/users",
            json={"username": username, "auth_password": auth_password}
        )
        if resp.status_code == 400 and "User exists" in resp.text:
            return unlock_vault(username, auth_password, master_password)
        resp.raise_for_status()
        data = resp.json()
        salt_hex = data.get("salt_kdf")
        if not salt_hex:
            print("No se recibió salt del backend")
            return False
        last_salt = bytes.fromhex(salt_hex)
    except Exception as e:
        print(f"Error registrando usuario: {e}")
        return None
    # Vault vacío inicial
    vault_data = {}
    master_key = master_password
    username_cache = username
    # Subir vault vacío cifrado (salt nuevo)
    blob = encrypt_vault(vault_data, master_password, username=username)
    new_salt = bytes.fromhex(blob["salt"])
    try:
        unlock_vault(username, auth_password, master_password)  # login y set_token
        resp = session.put(f"{BACKEND_URL}/api/vault", json=blob)
        resp.raise_for_status()
        last_salt = new_salt
        _update_client_salt(username, blob["salt"])
    except Exception as e:
        print(f"Error subiendo vault inicial: {e}")
        return None
    return unlock_vault(username, auth_password, master_password)

def unlock_vault(username, auth_password, master_password):
    global vault_data, master_key, username_cache, last_salt
    try:
        resp = session.post(
            f"{BACKEND_URL}/api/token",
            data={"username": username, "password": auth_password}
        )
        if resp.status_code != 200:
            print("Login fallido", resp.text)
            return None
        data = resp.json()
        set_token(data["access_token"])
    except Exception as e:
        print(f"Error en login: {e}")
        return None
    try:
        resp = session.get(f"{BACKEND_URL}/api/vault")
        if resp.status_code == 404:
            vault_data = {}
            master_key = master_password
            username_cache = username
            return vault_data
        resp.raise_for_status()
        blob = resp.json()
        
        # Validar que el blob tenga formato correcto antes de descifrar
        if not isinstance(blob, dict) or not all(k in blob for k in ["salt", "nonce", "ciphertext", "tag"]):
            print(f"Error: Blob del servidor tiene formato inválido: {blob}")
            return {"error": "MALFORMED_DATA", "message": "Vault data is corrupted on server"}
        
        # Usar el salt recibido para descifrar y para futuras escrituras
        decrypted = decrypt_vault(blob, master_password, username=username)
        
        # Manejar diferentes tipos de errores
        if isinstance(decrypted, dict) and "error" in decrypted:
            # Es un error de desencriptación, lo propagamos
            print(f"Error crítico: {decrypted['error']} - {decrypted['message']}")
            return decrypted
        
        if decrypted is None:
            print("Error crítico: login exitoso pero la desencriptación falló.")
            return {"error": "UNKNOWN_ERROR", "message": "Decryption failed for unknown reason"}
        
        vault_data = decrypted
        master_key = master_password
        username_cache = username
        
        # Guardar el salt para futuras escrituras (con validación)
        try:
            last_salt = bytes.fromhex(blob["salt"])
            _update_client_salt(username, blob.get("salt"))
        except ValueError as e:
            print(f"Error: Salt del servidor no es válido (hexadecimal): {e}")
            print(f"  Valor recibido: {blob.get('salt')}")
            return {"error": "MALFORMED_DATA", "message": "Server salt is not valid hexadecimal"}
        
        return vault_data
    except Exception as e:
        print(f"Error obteniendo vault: {e}")
        import traceback
        traceback.print_exc()
        return {"error": "NETWORK_ERROR", "message": str(e)}

def _persist_vault():
    global last_salt
    if not master_key:
        raise RuntimeError("No hay sesión activa")
    blob = encrypt_vault(vault_data, master_key, username=username_cache)
    new_salt = bytes.fromhex(blob["salt"])
    resp = session.put(f"{BACKEND_URL}/api/vault", json=blob)
    resp.raise_for_status()
    last_salt = new_salt
    _update_client_salt(username_cache, blob["salt"])
    return dict(vault_data)

def save_entry(entry_data, entry_id=None):
    global vault_data
    if not master_key or not username_cache:
        raise RuntimeError("No hay sesión activa")
    if entry_id is None:
        numeric_ids = []
        for key in vault_data.keys():
            try:
                numeric_ids.append(int(key))
            except (TypeError, ValueError):
                continue
        next_id = (max(numeric_ids) + 1) if numeric_ids else 1
        entry_id = str(next_id)
    else:
        entry_id = str(entry_id)
    vault_data[entry_id] = entry_data
    try:
        return _persist_vault()
    except Exception as e:
        print(f"Error guardando vault: {e}")
        raise

def delete_entry(entry_id):
    global vault_data
    if not master_key or not username_cache:
        raise RuntimeError("No hay sesión activa")
    entry_key = str(entry_id)
    if entry_key in vault_data:
        del vault_data[entry_key]
    try:
        return _persist_vault()
    except Exception as e:
        print(f"Error guardando vault: {e}")
        raise

def generate_password(length=16, use_uppercase=True, use_numbers=True, use_symbols=True):
    chars = string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))