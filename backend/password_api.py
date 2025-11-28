from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from jose import JWTError, jwt
from argon2 import PasswordHasher
from starlette.status import HTTP_401_UNAUTHORIZED
import uvicorn


# Simulated in-memory DB (replace with real DB in production)
users_db = {}  # username -> {hash, salt_kdf}
vaults_db = {}  # username -> vault blob

SECRET_KEY = "supersecretkey"  # Use a secure random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ph = PasswordHasher()

app = FastAPI(title="Password Manager Backend")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

class Token(BaseModel):
    access_token: str
    token_type: str

class UserCreate(BaseModel):
    username: str
    password: str

class VaultBlob(BaseModel):
    salt: str
    nonce: str
    ciphertext: str
    tag: str

# --- Auth helpers ---
def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain, hashed):
    try:
        ph.verify(hashed, plain)
        return True
    except Exception:
        return False

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in users_db:
            raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

# --- Endpoints ---
import os

@app.post("/api/users", summary="Register user")
def register(user: UserCreate):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User exists")
    # Generar salt de KDF y guardar junto al hash
    salt_kdf = os.urandom(16).hex()
    users_db[user.username] = {
        "hash": ph.hash(user.password),
        "salt_kdf": salt_kdf
    }
    return {"msg": "User registered", "salt_kdf": salt_kdf}

@app.post("/api/token", response_model=Token, summary="Login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hash"]):
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token({"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/api/vault", response_model=VaultBlob, summary="Get encrypted vault")
def get_vault(user: str = Depends(get_current_user)):
    blob = vaults_db.get(user)
    if not blob:
        raise HTTPException(status_code=404, detail="Vault not found")
    # Asegurarse de que el salt es el correcto (el del usuario)
    user_obj = users_db.get(user)
    if user_obj and "salt_kdf" in user_obj:
        blob["salt"] = user_obj["salt_kdf"]
    return blob

@app.put("/api/vault", summary="Update encrypted vault")
def update_vault(blob: VaultBlob, user: str = Depends(get_current_user)):
    # Siempre forzar el salt a ser el del usuario
    user_obj = users_db.get(user)
    if user_obj and "salt_kdf" in user_obj:
        blob.salt = user_obj["salt_kdf"]
    vaults_db[user] = blob.dict()
    return {"msg": "Vault updated"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
