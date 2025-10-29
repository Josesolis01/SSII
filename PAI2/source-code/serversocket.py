import socket
import ssl
import threading  # 1. Importamos el módulo de hilos
from messaging_service import ensure_tables
from auth_service import handle_registration, handle_login
from session_service import handle_session
from postgresql_functions import create_database_if_not_exists

HOST = "127.0.0.1"
PORT = 3030
certfile = 'certs/server.crt'
keyfile = 'certs/server.key'

# 2. Creamos una función que contiene TODA la lógica para un solo cliente.
#    Esto es lo que se ejecutará en cada hilo.
def handle_client_thread(conn, addr):
    print(f"Hilo iniciado para atender a {addr}")
    try:
        # El 'with conn:' asegura que la conexión se cierre al final del bloque
        with conn:
            # primer prompt: nuevo/login
            conn.sendall(b"Eres nuevo usuario o quieres loggearte? nuevo/login\n")
            data = conn.recv(1024)
            if not data:
                return
            opcion = data.decode().strip().lower()
            if opcion == "nuevo":
                _ = handle_registration(conn)
                conn.sendall(b"Eres nuevo usuario o quieres loggearte? nuevo/login\n")
                data = conn.recv(1024)
                if not data:
                    return
                opcion = data.decode().strip().lower()

            if opcion == "login":
                username = None
                while username is None:
                    username = handle_login(conn)
                    if username is None:
                        continue
                    try:
                        conn.sendall(b"oknonce\n")
                        _ = conn.recv(1024) # Esperar ACK del cliente
                    except Exception:
                        username = None
                        break
                    
                    # Iniciar la sesión persistente. El hilo se quedará aquí
                    # hasta que el cliente se desconecte o cierre sesión.
                    handle_session(conn, addr, username)
                    break # Salir del bucle de login
            else:
                conn.sendall(b"OPCION NO VALIDA, CERRANDO CONEXION\n")
    except (ConnectionResetError, BrokenPipeError):
        print(f"El cliente {addr} se desconectó abruptamente.")
    except Exception as e:
        print(f"Error en el hilo para {addr}: {e}")
    finally:
        print(f"Hilo para {addr} terminado.")

# --- Punto de entrada del Servidor ---
if __name__ == "__main__":
    create_database_if_not_exists()
    ensure_tables()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite reutilizar la dirección del socket rápidamente (útil en desarrollo)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(300) # Aumentamos la cola de conexiones pendientes

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    print(f"Servidor SSL Concurrente escuchando en {HOST}:{PORT}...")

    with ssl_context.wrap_socket(server_socket, server_side=True) as ssl_socket:
        while True:
            try:
                # 3. El bucle principal AHORA SOLO ACEPTA conexiones.
                conn, addr = ssl_socket.accept()
                
                # 4. Crea y lanza un nuevo hilo para cada conexión.
                thread = threading.Thread(target=handle_client_thread, args=(conn, addr))
                thread.daemon = True # El hilo no impedirá que el programa principal cierre
                thread.start()
            except KeyboardInterrupt:
                print("\nServidor detenido por el usuario.")
                break
            except Exception as e:
                print(f"Error aceptando conexiones: {e}")
    
    server_socket.close()
    print("Servidor cerrado.")