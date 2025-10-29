import socket
import ssl
import threading
import time
import sys
from postgresql_functions import crear_usuario, usuario_existe

# --- Configuración de la Prueba ---
HOST = "localhost"
PORT = 3030
CA_CERT = "certs/ca.crt"

NUM_CLIENTS = 300
TEST_USER_PREFIX = "testuser"
TEST_USER_PASS = "password123"

# --- Variables Globales para seguimiento (Versión Corregida) ---
active_connections = 0
connections_lock = threading.Lock() # 1. Usamos un Lock para proteger el contador
test_failed = threading.Event()

def prepare_test_users():
    """Registra los usuarios de prueba en la DB si no existen."""
    print("🔧 Preparando usuarios de prueba...")
    created_count = 0
    for i in range(NUM_CLIENTS):
        username = f"{TEST_USER_PREFIX}{i}"
        if not usuario_existe(username):
            ok, msg = crear_usuario(username, TEST_USER_PASS)
            if ok:
                created_count += 1
            else:
                print(f"Error creando {username}: {msg}")
                sys.exit(1)
    if created_count > 0:
        print(f"✅ {created_count} nuevos usuarios de prueba creados.")
    else:
        print("✅ Todos los usuarios de prueba ya existían.")

def client_thread(client_id: int):
    """Lógica para un solo cliente que se conecta y se mantiene vivo."""
    global active_connections # Necesario para modificar la variable global
    username = f"{TEST_USER_PREFIX}{client_id}"
    
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    
    try:
        with socket.create_connection((HOST, PORT)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=HOST) as ssock:
                # 1. Login automático
                ssock.recv(1024)
                ssock.sendall(b"login")
                ssock.recv(1024)
                ssock.sendall(username.encode())
                ssock.recv(1024)
                ssock.sendall(TEST_USER_PASS.encode())
                
                login_resp = ssock.recv(1024).decode()
                if "Login exitoso" not in login_resp:
                    print(f"[Cliente {client_id}] ❌ Login fallido: {login_resp.strip()}")
                    test_failed.set()
                    return

                ssock.recv(1024)
                ssock.sendall(b"ack")

                # 2. Incrementamos el contador de forma segura
                with connections_lock:
                    active_connections += 1
                
                # 3. Mantener la conexión abierta
                while not test_failed.is_set():
                    data = ssock.recv(4096)
                    if not data:
                        print(f"[Cliente {client_id}] ❌ Conexión cerrada inesperadamente por el servidor.")
                        test_failed.set()
                        break
                        
    except Exception as e:
        if not test_failed.is_set():
            print(f"[Cliente {client_id}]  Error: {e}")
            test_failed.set()
    finally:
        # 4. Decrementamos el contador de forma segura
        with connections_lock:
            active_connections -= 1

# --- Punto de entrada de la Prueba ---
if __name__ == "__main__":
    prepare_test_users()
    
    print(f"\n Iniciando prueba con {NUM_CLIENTS} conexiones simultáneas...")
    
    threads = []
    for i in range(NUM_CLIENTS):
        thread = threading.Thread(target=client_thread, args=(i,))
        threads.append(thread)
        thread.start()
        time.sleep(0.05)

    try:
        start_time = time.time()
        # Esperar a que todos los clientes se conecten
        while time.time() - start_time < 60: # Timeout de 60 segundos
            with connections_lock:
                current_connections = active_connections
            
            print(f"\r Tiempo: {int(time.time() - start_time)}s | 🟢 Conexiones activas: {current_connections}/{NUM_CLIENTS}", end="")

            if current_connections == NUM_CLIENTS:
                break
            
            if test_failed.is_set():
                break # Salir si se detecta un fallo
                
            time.sleep(1)

        print("\n") # Nueva línea después del contador

        if test_failed.is_set():
            print("---  PRUEBA FALLIDA: Se detectó un error en una de las conexiones. ---")
        elif active_connections < NUM_CLIENTS:
             print(f"---  PRUEBA FALLIDA: Timeout. Solo se establecieron {active_connections} de {NUM_CLIENTS} conexiones. ---")
        else:
            print(f"---  PRUEBA EXITOSA: Las {NUM_CLIENTS} conexiones están abiertas y persistentes. ---")
            print("Monitorizando estabilidad... (Detén con Ctrl+C)")
            while not test_failed.is_set():
                time.sleep(1)
            print("\n---  PRUEBA FALLIDA: Una conexión se cayó después del éxito inicial. ---")

    except KeyboardInterrupt:
        print("\n\nPrueba detenida por el usuario.")
        test_failed.set()

    print("Esperando que todos los hilos terminen...")
    for t in threads:
        t.join()
        
    print("Prueba finalizada.")