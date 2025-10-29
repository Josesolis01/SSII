# db_auth.py
import os
import bcrypt
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from nonce_functions import*
from datetime import datetime
from decimal import Decimal

# --- Configuración de conexión ---
# Usa variables de entorno o pon valores por defecto para desarrollo
DB_NAME = os.getenv("PGDATABASE", "ssiidb")
DB_USER = os.getenv("PGUSER", "postgres") # CAMBIAR POR USUARIO ADECUADO
DB_PASS = os.getenv("PGPASSWORD", "pua12398") # CAMBIAR POR CONTRASEÑA ADECUADA
DB_HOST = os.getenv("PGHOST", "127.0.0.1")
DB_PORT = os.getenv("PGPORT", "5432")

# --- INICIO DE LA NUEVA FUNCIÓN ---
def create_database_if_not_exists():
    """
    Se conecta al servidor PostgreSQL y crea la base de datos 'ssiidb' si no existe.
    Esta función debe ser llamada al inicio de la aplicación del servidor.
    """
    try:
        # Conectamos a la DB 'postgres' por defecto para tener permisos de creación
        conn = psycopg2.connect(
            dbname='postgres', user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
        )
        # CREATE DATABASE no puede ejecutarse en una transacción, usamos autocommit
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # Comprobamos si la base de datos ya existe
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}'")
        exists = cursor.fetchone()
        
        if not exists:
            print(f"La base de datos '{DB_NAME}' no existe. Creándola...")
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            # Después de crear la base de datos, podemos inicializar las tablas necesarias
            crear_usuario("Angel", "Angel123?")
            crear_usuario("Rafael", "Rafael123?")
            print("Base de datos creada exitosamente.")
        else:
            print(f"La base de datos '{DB_NAME}' ya existe. No se requiere ninguna acción.")
            
        cursor.close()
        conn.close()
        return True, "Inicialización de base de datos correcta."
    except psycopg2.OperationalError as e:
        # Este error suele ocurrir si el servicio de PostgreSQL no está corriendo
        return False, f"Error de conexión a PostgreSQL: {e}"
    except Exception as e:
        return False, f"Un error inesperado ocurrió: {e}"
# --- FIN DE LA NUEVA FUNCIÓN ---

@contextmanager
def get_conn():
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _get_user_hash(username: str):
    """Devuelve el hash (str) de bcrypt para un usuario o None si no existe."""
    q = "SELECT password FROM usuarios WHERE username = %s"
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q, (username,))
        row = cur.fetchone()
        return row[0] if row else None

# -----------------------------------------------------------
# 1) usuario_existe(usuario) -> bool
# -----------------------------------------------------------
def usuario_existe(usuario: str) -> bool:

    init_usuarios() # Asegura que la tabla exista
    q = "SELECT 1 FROM usuarios WHERE username = %s"
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q, (usuario,))
        return cur.fetchone() is not None

# -----------------------------------------------------------
# 2) crear_usuario(usuario, password) -> (bool, mensaje)
#   - Hashea con bcrypt y guarda en la tabla usuarios
#   - Devuelve True/False y mensaje explicativo
# -----------------------------------------------------------
def crear_usuario(usuario: str, password: str):
    init_usuarios() # Asegura que la tabla exista

    if not usuario or not password:
        return False, "Usuario y contraseña son obligatorios."

    # Reglas mínimas (opcional: ajusta a tus necesidades)
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."

    if usuario_existe(usuario):
        return False, "El usuario ya existe."
    
    # Generar hash bcrypt (es ASCII, lo guardamos como TEXT)
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    q = "INSERT INTO usuarios (username, password, cuenta) VALUES (%s, %s, 1000)"
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(q, (usuario, hashed))
        return True, "Usuario creado correctamente."
    except psycopg2.Error as e:
        # Si hay carreras de inserción, podría saltar unique_violation
        # 23505 = unique_violation
        if getattr(e, "pgcode", None) == "23505":
            return False, "El usuario ya existe."
        return False, f"Error de base de datos: {e.pgerror or str(e)}"
    
def init_usuarios():
    """Crea la tabla de usuarios si no existe (útil para desarrollo)."""
    q = """
    CREATE TABLE IF NOT EXISTS usuarios (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        cuenta NUMERIC DEFAULT 0
    )
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q)

# -----------------------------------------------------------
# 3) verificar_usuario(usuario, password) -> bool
#   - Comprueba usuario y contraseña con bcrypt
# -----------------------------------------------------------
def verificar_usuario(usuario: str, password: str) -> bool:
    stored_hash = _get_user_hash(usuario)
    if not stored_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        # Por si el hash en DB tuviera formato inesperado
        return False
    

#LEER SALDO DEL USUARIO LOGGEADO:

def leer_saldo_int(username: str) -> int | None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT cuenta FROM usuarios WHERE username = %s", (username,))
        fila = cur.fetchone()               # -> p.ej. (42,)
        if not fila or fila[0] is None:
            return None                     # no existe o saldo NULL
        saldo = int(fila[0])                # ya es int, conversión directa
        return saldo


# 3 TRANSACCION ---------------------------------------------------------------------------------

def ejecuta_transaccion(usuario, destinatario_esperado, paquete_transaccion, nonce_esperado):
    """
    Usa el destinatario esperado (por ejemplo tomado de la UI o sesión) como comprobación
    extra: debe coincidir con destinatario dentro del paquete firmado.
    """
    ok, msg = verify_transaction(paquete_transaccion, nonce_esperado)
    if not ok:
        raise ValueError(f"Verificación de la transacción fallida: {msg}")

    datos = paquete_transaccion.get("datos", {})
    destinatario_firmado = datos.get("destinatario")
    try:
        cantidad = int(datos.get("cantidad"))
    except Exception:
        raise ValueError("Cantidad en datos firmados no válida")

    if destinatario_firmado != destinatario_esperado:
        raise ValueError("Destinatario en datos firmado no coincide con el destinatario indicado")

    if usuario == destinatario_firmado:
        raise ValueError("No puedes transferirte a ti mismo.")
    if cantidad <= 0:
        raise ValueError("La cantidad debe ser mayor que 0.")
    
    # ---------------------------
    # Funciones de mensajería
    # ---------------------------
def init_mensajeria():
    """Crea la tabla de mensajes si no existe"""
    q = """
    CREATE TABLE IF NOT EXISTS mensajes (
        id SERIAL PRIMARY KEY,
        emisor TEXT NOT NULL,
        destinatario TEXT NOT NULL,
        contenido TEXT NOT NULL,
        fecha TIMESTAMP NOT NULL,
        leido BOOLEAN DEFAULT FALSE
    )
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q)


def enviar_mensaje(emisor: str, destinatario: str, contenido: str) -> bool:
    """Inserta un mensaje en la tabla `mensajes`. Devuelve True si tuvo éxito."""
    
    if len(contenido) > 144:
        raise ValueError("El contenido del mensaje no puede exceder 144 caracteres.")
    q = """ 
    INSERT INTO mensajes (emisor, destinatario, contenido, fecha, leido)
    VALUES (%s, %s, %s, %s, false)
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q, (emisor, destinatario, contenido, datetime.now()))
        return cur.rowcount == 1



def leer_mensajes(usuario: str) -> list:
    """Devuelve una lista de mensajes dirigidos a `usuario`.
    Cada mensaje es un dict: {emisor, contenido, fecha} con fecha formateada.
    Marca los mensajes como leídos.
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, emisor, contenido, fecha, leido FROM mensajes WHERE destinatario = %s ORDER BY fecha ASC",
            (usuario,),
        )
        rows = cur.fetchall()
        msgs = []
        ids = []
        for r in rows:
            ids.append(r[0])
            fecha = r[3]
            # Formato más agradable: DD/MM/YYYY HH:MM
            fecha_str = fecha.strftime("%d/%m/%Y %H:%M") if hasattr(fecha, "strftime") else str(fecha)
            msgs.append({
                'emisor': r[1],
                'contenido': r[2],
                'fecha': fecha_str,
            })

        if ids:
            # Marcar como leidos — usar ANY para pasar la lista correctamente a PostgreSQL
            cur.execute("UPDATE mensajes SET leido = TRUE WHERE id = ANY(%s)", (ids,))

        return msgs




                    
def registrar_transaccion(usuario, destinatario, valor):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO registro (emisor, destinatario, importe ,fecha)
            VALUES (%s, %s, %s, %s)
            """,
            (usuario, destinatario, Decimal(valor), datetime.now())
        )
        if cur.rowcount != 1:
            raise RuntimeError("No se pudo registrar la transacción.")