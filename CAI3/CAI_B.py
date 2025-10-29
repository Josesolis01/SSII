#!/usr/bin/env python3
"""
bruteforce_mac_20byte.py

Versión modificada: por defecto asume MAC de 20 bytes (p. ej. HMAC-SHA1 completo).
Incluye opción --algo para elegir el algoritmo hash (sha1 o sha256).

USO RESPONSABLE: Este script **solo** debe usarse en entornos controlados y
con autorización explícita. No lo uses contra sistemas reales sin permiso.

Entrada:
 - --mac : MAC objetivo en hex (ej: c5173b3e13fbed7f1b41c7dfa5fd6fd6368cd366)
 - --message : texto del mensaje a verificar OR --message-file ruta_a_fichero
 - --key-bits : número de bits del espacio de claves a buscar (p.ej. 24, 32)
 - --mac-bytes : número de bytes del MAC (por defecto 20 en esta versión).
 - --algo : algoritmo hash subyacente: 'sha1' o 'sha256' (por defecto 'sha1').
 - --parallel : usar multiprocessing (True/False)
 - --cpus : forzar número de procesos (por defecto cpu_count())

Ejemplo:
 python3 bruteforce_mac_20byte.py --mac c5173b3e13fbed7f1b41c7dfa5fd6fd6368cd366 \
   --message "531456_487654_200" --key-bits 24 --mac-bytes 20 --algo sha1

Salida:
 - Si encuentra clave, muestra valor entero y hex (apto para reproducir pruebas).
"""

import argparse
import hmac
import hashlib
import time
from multiprocessing import Pool, cpu_count


def parse_args():
    p = argparse.ArgumentParser(description="Brute-force MAC (HMAC truncatedisable).")
    p.add_argument("--mac", required=True, help="MAC objetivo en hex (ej: c5173b3e...)")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--message", help="Mensaje (texto) sobre el que se calculó la MAC")
    group.add_argument("--message-file", help="Leer mensaje desde fichero (binario)")
    p.add_argument("--key-bits", type=int, default=24, help="Bits del espacio de clave (p.ej. 24, 32)")
    p.add_argument("--mac-bytes", type=int, default=20, help="Número de bytes del MAC (por defecto 20).")
    p.add_argument("--algo", choices=("sha1", "sha256"), default="sha1",
                   help="Algoritmo hash subyacente para HMAC (sha1 -> 20 bytes, sha256 -> 32 bytes antes de truncar).")
    p.add_argument("--parallel", type=lambda s: s.lower() in ("true","1","yes"), default=False,
                   help="Usar multiprocessing (True/False).")
    p.add_argument("--cpus", type=int, default=None, help="Forzar número de procesos (por defecto cpu_count()).")
    return p.parse_args()


def load_message(args):
    if args.message:
        return args.message.encode()
    else:
        with open(args.message_file, "rb") as f:
            return f.read()


def mac_with_keyint(key_int, key_bytes_len, mac_bytes_len, message, hashfunc):
    key = key_int.to_bytes(key_bytes_len, "big")
    return hmac.new(key, message, hashfunc).digest()[:mac_bytes_len]


def brute_force_simple(target_mac_bytes, message, key_bits, mac_bytes_len, hashfunc):
    key_bytes_len = (key_bits + 7) // 8
    max_key = 1 << key_bits
    start = time.perf_counter()
    for k in range(max_key):
        if mac_with_keyint(k, key_bytes_len, mac_bytes_len, message, hashfunc) == target_mac_bytes:
            elapsed = time.perf_counter() - start
            return k, elapsed
    return None, None


# worker para búsqueda en un rango
def _worker_range(args):
    a, b, target_mac_bytes, message, key_bytes_len, mac_bytes_len, hashfunc = args
    for k in range(a, b):
        if hmac.new(k.to_bytes(key_bytes_len, "big"), message, hashfunc).digest()[:mac_bytes_len] == target_mac_bytes:
            return k
    return None


def brute_force_parallel(target_mac_bytes, message, key_bits, mac_bytes_len, hashfunc, nprocs=None):
    if nprocs is None:
        nprocs = cpu_count()
    key_bytes_len = (key_bits + 7) // 8
    max_key = 1 << key_bits
    chunk = (max_key + nprocs - 1) // nprocs
    ranges = []
    for i in range(nprocs):
        a = i * chunk
        b = min((i + 1) * chunk, max_key)
        if a < b:
            ranges.append((a, b, target_mac_bytes, message, key_bytes_len, mac_bytes_len, hashfunc))
    start = time.perf_counter()
    with Pool(nprocs) as pool:
        for res in pool.imap_unordered(_worker_range, ranges):
            if res is not None:
                elapsed = time.perf_counter() - start
                pool.terminate()
                return res, elapsed
    return None, None


def benchmark_hashrate(message, key_bytes_len, mac_bytes_len, hashfunc, iters=1000):
    # Mide cuántas HMACs/segundo con keys aleatorias (pequeña muestra)
    import os
    start = time.perf_counter()
    for i in range(iters):
        k = int.from_bytes(os.urandom(key_bytes_len), "big")
        _ = hmac.new(k.to_bytes(key_bytes_len, "big"), message, hashfunc).digest()[:mac_bytes_len]
    elapsed = time.perf_counter() - start
    return iters / elapsed if elapsed > 0 else float("inf")


def main():
    args = parse_args()
    message = load_message(args)
    try:
        target_mac_bytes = bytes.fromhex(args.mac)
    except Exception as e:
        print("Error: la MAC debe estar en formato hex válido (ej: a0902c7a).")
        raise

    # validar longitud
    if len(target_mac_bytes) != args.mac_bytes:
        print(f"ADVERTENCIA: la MAC proporcionada tiene {len(target_mac_bytes)} bytes, pero --mac-bytes={args.mac_bytes}.")
        print("Asegúrate de que --mac-bytes coincide con la longitud real de la MAC.")
        # no abortamos automáticamente; el usuario puede querer truncar/ajustar

    key_bits = args.key_bits
    mac_bytes_len = args.mac_bytes
    key_bytes_len = (key_bits + 7) // 8

    # seleccionar hashfunc
    if args.algo == "sha1":
        hashfunc = hashlib.sha1
    else:
        hashfunc = hashlib.sha256

    print(f"[INFO] Mensaje: {len(message)} bytes")
    print(f"[INFO] MAC objetivo: {args.mac} ({mac_bytes_len} bytes) — algoritmo: {args.algo}")
    print(f"[INFO] Espacio de claves: {key_bits} bits -> {1<<key_bits} posibles")
    print(f"[INFO] Key bytes (usar para to_bytes): {key_bytes_len}")

    # Medir tasa aproximada (local, secuencial)
    print("[INFO] Ejecutando benchmark de tasa HMAC (secuencial, muestra)...")
    hashrate = benchmark_hashrate(message, key_bytes_len, mac_bytes_len, hashfunc, iters=200)
    print(f"[INFO] Estimación inicial: {hashrate:.0f} HMAC/s por proceso (muestra).")

    if args.parallel:
        print(f"[INFO] Iniciando búsqueda paralela con {args.cpus or cpu_count()} procesos...")
        k, t = brute_force_parallel(target_mac_bytes, message, key_bits, mac_bytes_len, hashfunc, nprocs=args.cpus)
    else:
        print("[INFO] Iniciando búsqueda secuencial (single-process)...")
        k, t = brute_force_simple(target_mac_bytes, message, key_bits, mac_bytes_len, hashfunc)

    if k is None:
        print("[RESULT] No se encontró la clave en el espacio probado.")
    else:
        print(f"[RESULT] Clave encontrada: {k} (decimal) / 0x{k:0{key_bytes_len*2}x} (hex)")
        print(f"[RESULT] Tiempo empleado: {t:.3f} s")
        # Estimaciones
        espacio_total = 1 << key_bits
        intentos_medios = espacio_total / 2
        est_seconds = intentos_medios / hashrate / (args.cpus or 1) if hashrate>0 else float("inf")
        print(f"[EST] Tiempo medio esperado (con {args.cpus or 1} procesos y tasa actual): ~{est_seconds:.1f} s (~{est_seconds/3600:.2f} horas)")


if __name__ == "__main__":
    main()
