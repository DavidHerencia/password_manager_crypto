# Password Manager API Usage Examples

## Registro de usuario
```
POST /api/users
{
  "username": "usuario1",
  "password": "contraseña_segura"
}
```

## Login y obtención de JWT
```
POST /api/token (form-data)
username=usuario1
password=contraseña_segura

Respuesta:
{
  "access_token": "...jwt...",
  "token_type": "bearer"
}
```

## Guardar vault cifrado
```
PUT /api/vault
Headers: Authorization: Bearer <jwt>
{
  "salt": "...",
  "nonce": "...",
  "ciphertext": "...",
  "tag": "..."
}
```

## Obtener vault cifrado
```
GET /api/vault
Headers: Authorization: Bearer <jwt>
Respuesta:
{
  "salt": "...",
  "nonce": "...",
  "ciphertext": "...",
  "tag": "..."
}
```

- El campo `salt` siempre es el mismo para cada usuario.
- El backend nunca ve datos en texto plano.
- El JWT es obligatorio para todas las operaciones sobre el vault.
