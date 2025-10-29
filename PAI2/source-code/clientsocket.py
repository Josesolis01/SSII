import socket
from nonce_functions import *
import json
import secrets
import ssl
from postgresql_functions import usuario_existe
HOST = "localhost"
PORT = 3030
CERT_DIR = "certs"
CA_CERT = f"{CERT_DIR}/ca.crt"

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.load_verify_locations(CA_CERT)
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.check_hostname = True  # Asegúrate de que el cert tenga SAN/CN=localhost

MENU_MARK = b"Que deseas hacer?"

def mostrar_mensajes_si_hay(prefijo_bytes: bytes):

    data = prefijo_bytes.decode(errors="replace").strip()
    if not data:
        return
    try:
        msgs = json.loads(data)
        if not msgs:
            print("No hay mensajes nuevos.")
        else:
            print("Mensajes:\n")
            for m in msgs:
                print(f"De: {m['emisor']}  Fecha: {m['fecha']}\n  {m['contenido']}\n")
    except Exception:
        # No era JSON válido; imprime tal cual (p.ej., "No hay mensajes nuevos.\n")
        print(data)

with ssl_context.wrap_socket(client_socket, server_hostname=HOST) as s:
    s.connect((HOST, PORT))
    print(f"Conectado al servidor SSL en {HOST}:{PORT}")
    registro_exitoso = False

    pregunta = s.recv(1024).decode().strip()
    print(pregunta)

    opcion = input("> ").strip().lower()
    s.sendall(opcion.encode())

    if opcion == "nuevo":
        prompt_user = s.recv(1024).decode().strip()
        print(prompt_user)
        username = input("> ").strip()
        s.sendall(username.encode())

        while True:
            prompt_pass = s.recv(1024).decode().strip()
            print(prompt_pass)
            password = input("> ").strip()
            s.sendall(password.encode())

            resp = s.recv(1024).decode().strip()
            print(resp)

            if "Registro completado." in resp:
                opcion = "login"
                registro_exitoso = True
                break

    if opcion == "login":
        print("Implementando la funcionalidad de login\n")
        while True:
            prompt_user = s.recv(1024).decode().strip()
            print(prompt_user)

            username = input("> ").strip()
            s.sendall(username.encode())

            prompt_pass = s.recv(1024).decode().strip()
            print(prompt_pass)
            password = input("> ").strip()
            s.sendall(password.encode())

            resp = s.recv(1024).decode().strip()

            if "Login exitoso" in resp:
                # Handshake de nonce
                nonce_server = s.recv(1024).decode().strip()
                s.sendall(b"ack de nonce del servidor")

                # ===== BUCLE DE SESION =====
                while True:
                    buf = b""
                    while True:
                        chunk = s.recv(8192)
                        if not chunk:
                            print("Servidor cerró la conexión.")
                            exit(0)
                        buf += chunk
                        if MENU_MARK in buf:
                            break

                    # Separar lo que (posiblemente) sea JSON del menú
                    prefijo, resto = buf.split(MENU_MARK, 1)  # prefijo = JSON o texto; resto = resto del menú
                    # Mostrar mensajes si los hay (o texto tipo "No hay mensajes nuevos.")
                    mostrar_mensajes_si_hay(prefijo)

                    # Reconstruir menú completo y mostrar
                    menu_text = (MENU_MARK + resto).decode(errors="replace").strip()
                    print(menu_text)

                    
                    s.sendall(b"ack")
                        
                    # Enviar opción
                    opcion_sesion = input().strip()
                    s.sendall(opcion_sesion.encode())

                    if opcion_sesion == "1":
                        destinatario_prompt = s.recv(1024).decode().strip()
                        print(destinatario_prompt)
                        destinatario = input("> ").strip()
                        s.sendall(destinatario.encode())

                        contenido_prompt = s.recv(1024).decode().strip()
                        print(contenido_prompt)
                        contenido = input("> ").strip()
                        s.sendall(contenido.encode())

                        resultado = s.recv(1024).decode().strip()
                        print(resultado)

            elif "Usuario bloqueado temporalmente" in resp:
                print(resp)
            elif "intentos restantes" in resp:
                print(resp)
            else:
                print("usuario bloqueado o error no especificado")
                break
    else:
        print("Opción no reconocida. Terminando conexión.")
