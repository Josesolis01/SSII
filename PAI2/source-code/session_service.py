import socket
import json
from messaging_service import send_message, fetch_messages

MENU = (
    b"\nQue deseas hacer?\n"
    b"1. Enviar mensaje\n"
    b"2. Leer mensajes\n"
    b"3. Cerrar sesion\n"
    b">\n"
)

def handle_session(conn: socket.socket, addr, username: str):
    """Bucle de sesión: mantiene la conexión hasta que el usuario elija cerrar."""
    try:
        while True:
            # enviar menú y esperar ACK+opción en ese orden
            conn.sendall(MENU)
            ack = conn.recv(1024)  # ACK del cliente
            if not ack:
                break
            opcion_data = conn.recv(1024)
            print(f"Opcion recibida de {username}@{addr}: {opcion_data}")
            if not opcion_data:
                break
            opcion = opcion_data.decode().strip()
            payload = None
            mensaje = None

            if opcion == "1":
                print(f"Usuario {username} quiere enviar mensaje.")
                # Enviar prompt para el destinatario antes de recibirlo
                try:
                    conn.sendall(b"Introduce el nombre del destinatario:\n")
                except Exception:
                    break

                destinatario_data = conn.recv(1024)
                if not destinatario_data:
                    mensaje = "Destinatario no valido. Operacion cancelada.\n"
                else:
                    destinatario = destinatario_data.strip().decode("utf-8")
                    if not destinatario:
                        mensaje = "Destinatario no valido. Operacion cancelada.\n"
                    else:
                        try:
                            conn.sendall(b"Introduce el mensaje:\n")
                        except Exception:
                            break

                        contenido_data = conn.recv(4096)
                        if not contenido_data:
                            mensaje = "Contenido no recibido. Operacion cancelada.\n"
                        else:
                            contenido = contenido_data.strip().decode("utf-8")
                            ok = send_message(username, destinatario, contenido)
                            mensaje = "Mensaje enviado correctamente.\n" if ok else "Error al enviar el mensaje.\n"

            elif opcion == "2":
                msgs = fetch_messages(username)
                if not msgs:
                    mensaje = "No hay mensajes nuevos.\n"
                else:
                    payload = json.dumps(msgs)

            elif opcion == "3":
                try:
                    conn.sendall(b"Cerrando sesion. Adios.\n")
                except Exception:
                    pass
                break
            else:
                mensaje = "Opcion no valida.\n"

            # enviar payload o mensaje (antes del siguiente menú)
            if payload is not None:
                try:
                    conn.sendall(payload.encode())
                except Exception:
                    break
            elif mensaje is not None:
                try:
                    conn.sendall(mensaje.encode())
                except Exception:
                    break
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass