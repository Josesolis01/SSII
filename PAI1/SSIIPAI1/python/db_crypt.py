import socket
import sqlite3
import bcrypt

HOST = "127.0.0.1"
PORT = 3030

# Inicializar la base de datos
def init_db():
    conn = sqlite3.connect("usuarios.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Función para crear cuenta y guardar contraseña encriptada
def crear_cuenta(username, password):
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        conn = sqlite3.connect("usuarios.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        conn.close()
        return "✅ Usuario registrado con éxito"
    except sqlite3.IntegrityError:
        return "⚠️ El usuario ya existe"

# Servidor
def run_server():
    init_db()  # Asegura que la base de datos esté lista

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Servidor escuchando en {HOST}:{PORT}")
        conn, addr = s.accept()
        with conn:
            print(f"Conectado por {addr}")
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                mensaje = data.decode("utf-8").strip()
                
                # Suponemos que el cliente manda: "REGISTER usuario contraseña"
                if mensaje.startswith("REGISTER"):
                    try:
                        _, user, pwd = mensaje.split(" ", 2)
                        respuesta = crear_cuenta(user, pwd)
                    except ValueError:
                        respuesta = "❌ Formato inválido. Usa: REGISTER usuario contraseña"
                else:
                    respuesta = "Comando no reconocido"

                conn.sendall(respuesta.encode("utf-8"))

if __name__ == "__main__":
    run_server()
