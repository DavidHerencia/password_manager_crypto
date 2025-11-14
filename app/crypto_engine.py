#TODO LOGIC GEN, ENCK Y DECK
import random
import string

VAULT_EXISTS = True  # para testear creacion cambiar a false
CORRECT_USER = "admin"
CORRECT_PASS = "1234"
# -----------------------------

def check_db_exists(username):
    # TODO implementar (simulado)
    if username == CORRECT_USER and VAULT_EXISTS:
        return True
    return False

def create_vault(username, master_password):
    # TODO implementar (simulado)
    print(f"Creando bóveda para '{username}' con contraseña: {master_password}")
    # simulacion exitosa
    global VAULT_EXISTS, CORRECT_USER, CORRECT_PASS
    VAULT_EXISTS = True
    CORRECT_USER = username
    CORRECT_PASS = master_password
    return True

def unlock_vault(username, master_password):
    # TODO implementar (simulado)
    print(f"Intentando desbloquear bóveda para '{username}'")
    
    # Simula un login exitoso
    if username == CORRECT_USER and master_password == CORRECT_PASS:
        print("Bóveda desbloqueada.")
        # llenar la tabla
        return {
            1: {"service": "Google", "username": "test@gmail.com", "password": "g_password_123!"},
            2: {"service": "GitHub", "username": "testuser_dev", "password": "gh_password_456#"},
            3: {"service": "Discord", "username": "gamer_tag", "password": "my_secret_discord_pass"},
            4: {"service": "Amazon", "username": "buyer@email.com", "password": "amazon_shopping_key"},
        }
    
    # Simula un login fallido
    print("Usuario o contraseña incorrecta.")
    return None

def save_entry(entry_data):
    # TODO implementar (simulado)
    print(f"Simulando guardado de: {entry_data}")

def delete_entry(entry_id):
    # TODO implementar (simulado)
    print(f"Simulando eliminación de entrada con ID: {entry_id}")

def generate_password(length=16, use_uppercase=True, use_numbers=True, use_symbols=True):
    # TODO implementar (simulado)
    
    chars = string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_numbers:
        chars += string.digits
    if use_symbols:
        chars += string.punctuation
        
    return ''.join(random.choice(chars) for _ in range(length))