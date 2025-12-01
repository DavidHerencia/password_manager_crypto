from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from jose import JWTError, jwt
from argon2 import PasswordHasher
from starlette.status import HTTP_401_UNAUTHORIZED
import uvicorn
import os

# --- Módulo de Base de Datos ---
import database
# --- Configuración ---
SECRET_KEY = "criptoRules123"  # Usar una clave segura y aleatoria en producción
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ph = PasswordHasher()
app = FastAPI(title="Password Manager Backend")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

# --- Modelos de Datos ---
class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    password: str

class VaultBlob(BaseModel):
    # Incluye los parámetros necesarios para reconstruir la llave y descifrar el vault
    salt: str
    nonce: str
    ciphertext: str
    tag: str

# --- Helpers de Autenticación ---
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain, hashed):
    try:
        ph.verify(hashed, plain)
        return True
    except Exception:
        return False

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decodifica el token JWT para obtener el usuario actual."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
        # Verificar que el usuario todavía existe en la BD
        user_data = database.get_user(username)
        if user_data is None:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="User not found")
            
        return user_data # Retorna el objeto del usuario de la BD
    except JWTError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

# --- Endpoints ---

@app.on_event("startup")
def on_startup():
    """Inicializa la base de datos al iniciar la aplicación."""
    database.init_db()

@app.post("/api/users", summary="Register user")
def register(user: UserCreate):
    """Registra un nuevo usuario en la base de datos."""
    if database.get_user(user.username):
        raise HTTPException(status_code=400, detail="User already exists")
    
    salt_kdf = os.urandom(16).hex()
    hashed_password = ph.hash(user.password)
    
    success = database.create_user(user.username, hashed_password, salt_kdf)
    if not success:
        raise HTTPException(status_code=500, detail="Could not create user")
        
    return {"msg": "User registered successfully", "salt_kdf": salt_kdf}

@app.post("/api/token", response_model=Token, summary="Login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Autentica a un usuario y retorna un token de acceso."""
    user = database.get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hash"]):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    
    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/vault", summary="Get encrypted vault", response_model=VaultBlob)
def get_vault(current_user: dict = Depends(get_current_user)):
    """Obtiene la bóveda cifrada para el usuario autenticado."""
    username = current_user["username"]
    vault = database.get_vault(username)

    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")

    if "salt" not in vault:
        # Compatibilidad con registros antiguos que no guardaban el salt en el blob
        vault = {**vault, "salt": current_user["salt_kdf"]}

    return vault

@app.put("/api/vault", summary="Update or create encrypted vault")
def update_vault(blob: VaultBlob, current_user: dict = Depends(get_current_user)):
    """Actualiza (o crea) la bóveda encriptada para el usuario autenticado."""
    username = current_user["username"]
    
    # El blob que llega del cliente contiene nonce, ciphertext y tag.
    # Lo guardamos directamente en la base de datos.
    success = database.update_or_create_vault(username, blob.dict())
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update vault")
        
    return {"msg": "Vault updated successfully"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)