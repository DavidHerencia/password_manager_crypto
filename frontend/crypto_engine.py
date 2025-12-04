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
from pathlib import Path

# Carpeta local para almacenar secretos del cliente (pepper y salt locales)
CONFIG_DIR = Path.home() / ".password_manager_crypto"
CLIENT_SECRETS_FILE = CONFIG_DIR / "client_secrets.json"

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

_client_secrets_cache: dict[str, str] | None = None


def _load_or_create_client_secrets() -> dict[str, str]:
    """Obtiene (o genera) el pepper y salt locales del cliente."""
    global _client_secrets_cache

    if _client_secrets_cache is not None:
        return _client_secrets_cache

    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            CONFIG_DIR.chmod(0o700)
    except Exception as exc:
        raise RuntimeError("No se pudo preparar la carpeta de configuración local") from exc

    if CLIENT_SECRETS_FILE.exists():
        try:
            with CLIENT_SECRETS_FILE.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            raise RuntimeError("No se pudo leer el archivo de secretos del cliente") from exc

        if not isinstance(data, dict) or "pepper" not in data or "client_salt" not in data:
            raise RuntimeError("El archivo de secretos del cliente no tiene el formato esperado")

        _client_secrets_cache = data
        return data

    secrets_payload = {
        "pepper": secrets.token_hex(32),
        "client_salt": secrets.token_hex(32)
    }

    with CLIENT_SECRETS_FILE.open("w", encoding="utf-8") as fh:
        json.dump(secrets_payload, fh)

    if os.name != "nt":
        os.chmod(CLIENT_SECRETS_FILE, 0o600)

    _client_secrets_cache = secrets_payload
    return secrets_payload

def set_token(jwt):
    global token
    token = jwt
    session.headers.update({"Authorization": f"Bearer {jwt}"})

def derive_key(password: str, salt: bytes) -> bytes:
    # Usa Argon2id para derivar la clave AES-256, combinando password y secretos locales
    from argon2.low_level import hash_secret_raw, Type
    secrets_payload = _load_or_create_client_secrets()
    pepper_bytes = bytes.fromhex(secrets_payload["pepper"])
    client_salt_bytes = bytes.fromhex(secrets_payload["client_salt"])
    secret = password.encode("utf-8") + pepper_bytes + client_salt_bytes
    return hash_secret_raw(
        secret, salt,
        time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID
    )

def encrypt_vault(vault_dict, password, salt=None):
    # Serializa y cifra el vault dict
    if salt is None:
        # Si no hay salt, generamos uno nuevo (solo para vault nuevo)
        salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    data = json.dumps(vault_dict).encode()
    ct = aesgcm.encrypt(nonce, data, None)
    ciphertext, tag = ct[:-16], ct[-16:]
    return {
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }

def decrypt_vault(blob, password):
    try:
        salt_hex = blob["salt"]
        nonce_hex = blob["nonce"]
        ciphertext_hex = blob["ciphertext"]
        tag_hex = blob["tag"]
    except KeyError as exc:
        print(f"Campos faltantes en el blob cifrado: {exc}")
        return {}

    try:
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
    except ValueError as exc:
        print(f"Formato inválido en el blob cifrado: {exc}")
        return {}

    ct = ciphertext + tag

    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(nonce, ct, None)
        return json.loads(data.decode())
    except Exception as e:
        print(f"Error descifrando vault con secretos locales: {e}")

    # Intento de compatibilidad con versiones anteriores que usaban un pepper global fijo
    try:
        from argon2.low_level import hash_secret_raw, Type

        legacy_secret = (password + "pepper_super_secreto").encode("utf-8")
        legacy_key = hash_secret_raw(
            legacy_secret,
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            type=Type.ID,
        )
        aesgcm = AESGCM(legacy_key)
        ct = ciphertext + tag
        data = aesgcm.decrypt(nonce, ct, None)
        print("Vault descifrado con pepper legado; se rotará al guardar cambios.")
        return json.loads(data.decode())
    except Exception as legacy_error:
        print(f"Error descifrando vault con pepper legado: {legacy_error}")
        return {}

def create_vault(username, master_password):
    global vault_data, master_key, username_cache, last_salt
    try:
        resp = session.post(f"{BACKEND_URL}/api/users", json={"username": username, "password": master_password})
        if resp.status_code == 400 and "User exists" in resp.text:
            return unlock_vault(username, master_password)
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
    blob = encrypt_vault(vault_data, master_password, salt=last_salt)
    try:
        unlock_vault(username, master_password)  # login y set_token
        resp = session.put(f"{BACKEND_URL}/api/vault", json=blob)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error subiendo vault inicial: {e}")
        return None
    return unlock_vault(username, master_password)

def unlock_vault(username, master_password):
    global vault_data, master_key, username_cache, last_salt
    try:
        resp = session.post(f"{BACKEND_URL}/api/token", data={"username": username, "password": master_password})
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
        # Usar el salt recibido para descifrar y para futuras escrituras
        vault_data = decrypt_vault(blob, master_password)
        master_key = master_password
        username_cache = username
        # Guardar el salt para futuras escrituras
        last_salt = bytes.fromhex(blob["salt"])
        return vault_data
    except Exception as e:
        print(f"Error obteniendo vault: {e}")
        return None

def _persist_vault():
    if not master_key:
        raise RuntimeError("No hay sesión activa")
    if last_salt is None:
        raise RuntimeError("No hay salt disponible para el vault")
    blob = encrypt_vault(vault_data, master_key, salt=last_salt)
    resp = session.put(f"{BACKEND_URL}/api/vault", json=blob)
    resp.raise_for_status()
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