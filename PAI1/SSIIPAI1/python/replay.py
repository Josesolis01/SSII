#!/usr/bin/env python3
# -- coding: utf-8 --
import socket, json, secrets, time
import base64, hmac, hashlib
from typing import Dict, Any, Tuple

HOST = "127.0.0.1"
PORT = 3030

SECRET_KEY = b"Tu_Clave_Secreta_HMAC"

def datos_transaccion(valor, destinatario, nonce_server):
    nonce_client = secrets.token_hex(16)
    ts = int(time.time())

    datos = {
        "cantidad": valor,
        "destinatario": destinatario,
        "nonce_client": nonce_client,
        "nonce_server": nonce_server,
        "timestamp": ts
    }

    datos_byte = json.dumps(datos, sort_keys=True).encode()
    firma = hmac.new(SECRET_KEY, datos_byte, hashlib.sha256).hexdigest()

    return {
        "datos": datos,
        "firma": firma
    }

def ejecutar_ataque_replay(username: str, password: str, destinatario: str, cantidad: str):
    print("Iniciando Ataque de Reenvío contra el Servidor...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            print("\n--- 1. FASE DE LOGIN Y NONCE ---")

            s.recv(1024)
            s.sendall(b"login")

            s.recv(1024)
            s.sendall(username.encode())
            s.recv(1024)
            s.sendall(password.encode())

            resp_login = s.recv(1024).decode().strip()
            print(f"[SERVIDOR] {resp_login}")

            if "Login exitoso" not in resp_login:
                print("ERROR: Login fallido. Abortando ataque.")
                return

            nonce_server = s.recv(1024).decode().strip()
            s.sendall(b"ack de nonce del servidor")
            print(f"Nonce del servidor capturado: {nonce_server[:8]}...")

            s.recv(1024)
            s.sendall(b"ack")

            print("\n--- 2. FASE DE CAPTURA DEL PAQUETE ---")

            s.sendall(b"1")
            s.recv(1024)

            s.recv(1024)
            s.sendall(destinatario.encode())

            s.recv(4096)
            s.sendall(cantidad.encode())
            s.recv(1024)

            datos_tx = datos_transaccion(cantidad, destinatario, nonce_server)
            paquete_ataque = json.dumps(datos_tx).encode()

            nonce_usado = datos_tx['datos']['nonce_client'][:8]
            print(f"Paquete TX generado (Nonce: {nonce_usado}...)")

            print("\n[CLIENTE 1/2] Enviando paquete legítimo (se espera éxito)...")
            s.sendall(paquete_ataque)

            resp_ack_1 = s.recv(1024).decode().strip()
            print(f"[SERVIDOR 1ª RESPUESTA (ACK)]: {resp_ack_1}")

            print("\n[CLIENTE 2/2] *** SIMULANDO REPLAY ***")
            print(f"[CLIENTE 2/2] Reenviando el MISMO paquete (Nonce: {nonce_usado}...)")
            s.sendall(paquete_ataque)

            resp_final_1 = s.recv(4096).decode().strip()
            print(f"[SERVIDOR 1ª RESPUESTA FINAL]: {resp_final_1}")

            if "Transaccion exitosa" not in resp_final_1:
                print("ERROR CRÍTICO: La primera transacción falló. No se puede simular el replay.")
                return

            s.sendall(b"ack de nonce del cliente")

            s.recv(1024)
            s.sendall(b"ack")
            s.recv(1024)
            s.sendall(b"1")

            s.recv(1024)

            s.recv(1024); s.sendall(destinatario.encode())
            s.recv(4096); s.sendall(cantidad.encode())
            s.recv(1024)

            print("\n[CLIENTE 2/2] RE-INYECCIÓN: Reenviando paquete capturado...")
            s.sendall(paquete_ataque)

            resp_ack_2 = s.recv(1024).decode().strip()
            print(f"[SERVIDOR 2ª RESPUESTA (ACK)]: {resp_ack_2}")

            resp_final_2 = s.recv(4096).decode().strip()
            print(f"[SERVIDOR 2ª RESPUESTA FINAL]: {resp_final_2}")

            print("\n" + "="*60)
            if "Replay detectado" in resp_final_2 or "nonce repetido" in resp_final_2:
                print("DEFENSA EXITOSA: El servidor detectó el Nonce repetido y rechazó el Reenvío.")
            else:
                print("FALLO DE DEFENSA: El servidor procesó la transacción duplicada.")
            print("="*60)


    except ConnectionRefusedError:
        print("\nERROR DE CONEXIÓN: El servidor no está activo o escuchando en el puerto 3030.")
        print("Asegúrate de que 'serversocket.py' se está ejecutando en otra terminal.")
    except Exception as e:
        print(f"\nERROR EN EL FLUJO: El servidor cerró la conexión inesperadamente o hubo un fallo de protocolo: {e}")

USUARIO_ATACANTE = "luis"
PASSWORD_VALIDA = "Plapino123?"
DESTINATARIO = "marta"
CANTIDAD_A_TRANSFERIR = "10"

ejecutar_ataque_replay(USUARIO_ATACANTE, PASSWORD_VALIDA, DESTINATARIO, CANTIDAD_A_TRANSFERIR)
