import socket
import os
import bcrypt
import secrets
import time
import hmac
import hashlib
import json

def _load_secret():
    s = os.environ.get("SECRET_KEY")
    if not s:
        # En prod, mejor lanzar excepción
        # raise RuntimeError("SECRET_KEY no definida")
        s = "clave_dev_solo_pruebas"
    return s.encode()


SECRET_KEY = _load_secret()
used_nonces = set()
ALLOWED_DRIFT = 30

def verify_transaction(datos_transaccion, issued_nonce_server):
    try:
        datos = datos_transaccion["datos"]
        firma = datos_transaccion["firma"]

        # 1) Verificar timestamp
        now = int(time.time())
        if abs(now - datos["timestamp"]) > ALLOWED_DRIFT:
            return False, "Timestamp fuera de ventana"

        # 2) Verificar nonce del servidor
        if datos["nonce_server"] != issued_nonce_server:
            return False, "Nonce de servidor inválido"

        # 3) Verificar nonce del client no reutilizado
        if datos["nonce_client"] in used_nonces:
            return False, "Nonce del client ya usado"
        used_nonces.add(datos["nonce_client"])

        # 4) Verificar firma HMAC
        expected = hmac.new(
            SECRET_KEY,
            json.dumps(datos, sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, firma):
            return False, " Firma inválida"

        return True, "✅ Transacción válida"
    except Exception as e:
        return False, f" Error en verificación: {e}"

def datos_transaccion(valor, destinatario, nonce_server):

    nonce_client = secrets.token_hex(16)
    ts = int(time.time())


    datos={
        "cantidad": valor,
        "destinatario": destinatario,
        "nonce_client": nonce_client,
        "nonce_server": nonce_server,
        "timestamp": ts
    }

    datos_byte= json.dumps(datos,sort_keys=True).encode()
    firma = hmac.new(SECRET_KEY, datos_byte, hashlib.sha256).hexdigest()

    return {
        "datos": datos, 
        "firma": firma
    }
