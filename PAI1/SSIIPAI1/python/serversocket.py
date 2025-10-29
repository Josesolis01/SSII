import socket
import os
import bcrypt
from postgresql_functions import *
from nonce_functions import *
import json
from time_functions import *
import secrets

HOST = "127.0.0.1"
PORT = 3030

def is_strong_password(password):
    if len(password) < 8:
        return False, "La contrasena debe tener al menos 8 caracteres."
    if not any(char.isdigit() for char in password.decode()):
        return False, "La contrasena debe contener al menos un numero."
    if not any(char.isalpha() for char in password.decode()):
        return False, "La contrasena debe contener al menos una letra."
    if not any(char in "!@#$%^&*()_+-=[]{}|;':\",.<>/?`~" for char in password.decode()):
        return False, "La contrasena debe contener al menos un simbolo."
    return True, ""

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        conn.sendall(b"Eres nuevo usuario o quieres loggearte? nuevo/login\n")

        data = conn.recv(1024)
        if data:
            opcion = data.decode().strip().lower()
            print(f"Respuesta del cliente: {opcion}")

            if opcion == "nuevo":
                conn.sendall(b"Introduce un nombre de usuario:\n")

                username = conn.recv(1024).decode().strip()
                print("Nombre de usuario:" + username)
                if usuario_existe(username):
                    conn.sendall(b"Usuario ya existe. Prueba con otro.\n")
                else:
                   while True:
                        conn.sendall(b"Introduce una contrasena:\n")
                        password = conn.recv(1024).strip()

                        is_valid, reason = is_strong_password(password)

                        if is_valid:
                            password_txt = password.decode("utf-8")
                            crear_usuario(username, password_txt)
                            conn.sendall(b"Registro completado. Por favor, inicia sesion a continuacion.\n")
                            opcion = "login"
                            break
                        else:
                            conn.sendall(reason.encode() + b"\n")

            if opcion == "login":

                while True:
                    conn.sendall(b"Introduce un nombre de usuario:\n")
                    username = conn.recv(1024).decode().strip()
                    print("Nombre de usuario: " + username)
                    is_locked, tiempo_restante = bloqueado(username)
                    if is_locked is True:
                        msg = f"Usuario bloqueado temporalmente. Intente de nuevo en {tiempo_restante} segundos.\n"
                        conn.sendall(msg.encode())
                        continue
                    else:
                        conn.sendall(b"Introduce una contrasena:\n")
                        password = conn.recv(1024).strip()

                    if usuario_existe(username):
                        password_txt = password.decode("utf-8")
                        verficacion = verificar_usuario(username, password_txt)
                        if verficacion == False:
                            is_locked, restantes = registrar_fallo(username)
                            if is_locked:
                                msg = f"Usuario bloqueado por {LOCK_SECONDS} segundos.\n"
                                conn.sendall(msg.encode())
                                continue
                            else:
                                msg = f"intentos restantes: {restantes}. Vuelve a intentarlo"
                                conn.sendall(msg.encode())

                        else:
                            conn.sendall(b"Login exitoso.\n")
                            nonce_server = secrets.token_hex(16)
                            conn.sendall(nonce_server.encode())

                            ACK = conn.recv(1024)

                            menu = (
                            b"\nQue deseas hacer?\n"
                            b"1. Transaccion\n"
                            b"2. Cerrar sesion\n"
                            )
                            conn.sendall(menu)
                            print("Menu enviado, esperando ACK...")
                            ACK = conn.recv(1024)
                            print(ACK)
                            if not ACK:
                                break

                            opcion_sesion_data = conn.recv(1024)
                            print(opcion_sesion_data)
                            if not opcion_sesion_data:
                                break

                            opcion_sesion = opcion_sesion_data.decode().strip()

                            if opcion_sesion == "1":
                                conn.sendall(b"Iniciando transaccion.\n")

                                conn.sendall(b"Introduce el nombre del destinatario:\n")

                                destinatario = conn.recv(1024).strip()
                                destinatario = destinatario.decode("utf-8")

                                if not usuario_existe(destinatario):
                                    conn.sendall(b"\n Error: El destinatario no existe. Transaccion cancelada.\n")
                                    continue
                                else:
                                    print("usuario verificado")
                                    saldo = leer_saldo_int(username)
                                    mensaje = f"{saldo} \n"
                                    conn.sendall(f"Su saldo en cuenta es:\n{mensaje}\nIntroduce la cantidad a transferir:\n".encode())

                                    cantidad = conn.recv(1024).strip()
                                    cantidad = cantidad.decode("utf-8")
                                    print("cantidad recibida: " + cantidad)
                                    conn.sendall(b"ack de la cantidad")

                                raw_datos = conn.recv(4096).strip()
                                datos_trans = json.loads(raw_datos.decode())
                                conn.sendall(b"ack de los datos")
                                if verificar_usuario(username, password_txt):
                                    ejecuta_transaccion(username, destinatario, datos_trans, nonce_server)
                                    nonce_cliente = conn.recv(1024).strip()
                                    conn.sendall(b"ack del nonce del cliente")
                                    mensaje = (
                                        f"\n✅ Transaccion exitosa:\n"
                                        f"   Destinatario: {destinatario}\n"
                                        f"   Cantidas: {cantidad}\n"
                                        f"   (Confirmado con contrasena).\n"
                                    )
                                    conn.sendall(mensaje.encode())
                                else:
                                    conn.sendall(b"\n Contrasena de confirmacion incorrecta. Transaccion cancelada.\n")

                            elif opcion_sesion == "2":
                                conn.sendall(b"Cerrando sesion. Adios.\n")
                                break

                            else:
                                conn.sendall(b"Opcion no valida.\n")

                            break

            else:
                conn.sendall(b"Usuario o contrasena incorrectos (FINAL).\n")
