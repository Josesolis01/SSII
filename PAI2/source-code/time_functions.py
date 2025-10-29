import time

##################Gestión de usuarios##################
# Config
MAX_ATTEMPTS = 3
LOCK_SECONDS = 300  # 5 minutos

# Estado en memoria
FAILED_LOGINS = {}    # username -> num fallos
LOCKED_USERS = {}

def now():
    """Devuelve la hora actual en segundos desde la época."""
    return int(time.time())

def bloqueado(usuario):

    until = LOCKED_USERS.get(usuario)
    if until is None:
        return False, 0
    if now() > until:
        del LOCKED_USERS[usuario]
        FAILED_LOGINS[usuario] = 0
        return False, 0
    return True, int(until - now())


def registrar_fallo(usuario):
    """Registra un fallo de login para el usuario. Devuelve True si el usuario queda bloqueado."""
    if usuario not in FAILED_LOGINS:
        FAILED_LOGINS[usuario] = 0
    FAILED_LOGINS[usuario] += 1
    intentos_restantes = MAX_ATTEMPTS - FAILED_LOGINS[usuario]
    if FAILED_LOGINS[usuario] >= MAX_ATTEMPTS:
        LOCKED_USERS[usuario] = now() + LOCK_SECONDS
        return True, 0
    return False, intentos_restantes

def reset_fallos(usuario):
    """Resetea el contador de fallos de login para el usuario."""
    if usuario in FAILED_LOGINS:
        del FAILED_LOGINS[usuario]