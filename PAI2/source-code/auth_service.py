import socket
from postgresql_functions import usuario_existe, crear_usuario, verificar_usuario
from time_functions import bloqueado, registrar_fallo, LOCK_SECONDS

def handle_registration(conn: socket.socket) -> str | None:
    conn.sendall(b"Introduce un nombre de usuario:\n")
    username = conn.recv(1024).decode().strip()
    if usuario_existe(username):
        conn.sendall(b"Usuario ya existe. Prueba con otro.\n")
        return None
    # pedir contraseña y validarla en el caller (o aquí)
    conn.sendall(b"Introduce una contrasena:\n")
    password = conn.recv(1024).strip().decode("utf-8")
    ok, msg = crear_usuario(username, password)
    if ok:
        conn.sendall(b"Registro completado. Por favor, inicia sesion a continuacion.\n")
        return None  # fuerza al cliente a loguearse después
    else:
        conn.sendall(msg.encode() + b"\n")
        return None

def handle_login(conn: socket.socket) -> str | None:
    # devuelve username si login OK, None en caso contrario
    conn.sendall(b"Introduce un nombre de usuario:\n")
    username = conn.recv(1024).decode().strip()
    is_locked, seconds = bloqueado(username)
    if is_locked:
        msg = f"Usuario bloqueado temporalmente. Intente de nuevo en {seconds} segundos.\n"
        conn.sendall(msg.encode())
        return None
    conn.sendall(b"Introduce una contrasena:\n")
    password = conn.recv(1024).strip().decode("utf-8")
    if not usuario_existe(username):
        conn.sendall(b"Usuario o contrasena incorrectos.\n")
        return None
    if not verificar_usuario(username, password):
        locked, remaining = registrar_fallo(username)
        if locked:
            conn.sendall(f"Usuario bloqueado por {LOCK_SECONDS} segundos.\n".encode())
        else:
            conn.sendall(f"intentos restantes: {remaining}. Vuelve a intentarlo\n".encode())
        return None
    conn.sendall(b"Login exitoso.\n")
    return username