# db_auth.py
import os
import bcrypt
import psycopg2
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from nonce_functions import*
from datetime import datetime
# --- Configuración de conexión ---
# Usa variables de entorno o pon valores por defecto para desarrollo
DB_NAME = os.getenv("PGDATABASE", "ssiidb")
DB_USER = os.getenv("PGUSER", "postgres")
DB_PASS = os.getenv("PGPASSWORD", "pua12398")
DB_HOST = os.getenv("PGHOST", "127.0.0.1")
DB_PORT = os.getenv("PGPORT", "5432")

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

    # Operación atómica igual que en la opción A
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT username, cuenta FROM usuarios
                WHERE username IN (%s, %s)
                FOR UPDATE
                """,
                (usuario, destinatario_firmado)
            )
            filas = cur.fetchall()
            if len(filas) < 2:
                raise ValueError("Usuario origen o destinatario no existe.")

            saldos = {row[0]: int(row[1]) for row in filas}
            saldo_usuario = saldos.get(usuario, 0)
            saldo_destinatario = saldos.get(destinatario_firmado, 0)

            if saldo_usuario < cantidad:
                raise ValueError("Saldo insuficiente en la cuenta de origen.")

            nuevo_saldo_usuario = saldo_usuario - cantidad
            nuevo_saldo_destinatario = saldo_destinatario + cantidad

            cur.execute(
                "UPDATE usuarios SET cuenta = %s WHERE username = %s",
                (nuevo_saldo_usuario, usuario)
            )
            if cur.rowcount != 1:
                raise RuntimeError("No se pudo actualizar el saldo del usuario origen.")

            cur.execute(
                "UPDATE usuarios SET cuenta = %s WHERE username = %s",
                (nuevo_saldo_destinatario, destinatario_firmado)
            )
            if cur.rowcount != 1:
                raise RuntimeError("No se pudo actualizar el saldo del destinatario.")

            registrar_transaccion(usuario, destinatario_firmado, cantidad)
            
    return True

                    
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
        

