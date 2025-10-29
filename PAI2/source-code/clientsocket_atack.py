# clientsocket_atack.py
import socket
from nonce_functions import*
import json  
import secrets  # <-- añade esto


HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 3030         # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    registro_exitoso = False    

    # 1) Recibir la pregunta inicial del servidor
    pregunta = s.recv(1024).decode().strip()
    print(pregunta)

    # 2) Responder: escribe 'nuevo' para registrar
    opcion = input("> ").strip().lower()
    s.sendall(opcion.encode())

    if opcion == "nuevo":
        # 3) Recibir prompt de usuario y responder
        prompt_user = s.recv(1024).decode().strip()
        print(prompt_user)
        username = input("> ").strip()
        s.sendall(username.encode())

        #Bucle por si falla la contraseña y hay que volver a pedirla
        while True: 
            # 4) Recibir prompt de contraseña y responder
            prompt_pass = s.recv(1024).decode().strip()
            print(prompt_pass)
            password = input("> ").strip()
            s.sendall(password.encode())

            # 5) Recibir confirmación de registro
            resp = s.recv(1024).decode().strip()
            print(resp)

            # 6) Comprobar si el registro fue exitoso
            if "Registro completado." in resp:
                opcion = "login" 
                registro_exitoso = True
                break # Salir del bucle si la contraseña es válid


    if opcion == "login":
        print("Implementando la funcionalidad de login\n")
            # Si se acaba de registrar, no es necesario volver a pedir 'login'
        while True:
        

        # 3) Recibir prompt de usuario y responder
            prompt_user = s.recv(1024).decode().strip()
            print(prompt_user)

            username = input("> ").strip()
            s.sendall(username.encode())

            # 4) Recibir prompt de contraseña y responder
            prompt_pass = s.recv(1024).decode().strip()
            print(prompt_pass)
            password = input("> ").strip()

            s.sendall(password.encode())

            # 5) Recibir confirmación de registro
            resp = s.recv(1024).decode().strip()
            print(resp)

            # 6) Si el Login es exitoso, entra en el bucle de sesión interactiva
            if "Login exitoso" in resp:
                # recibe nonce del servidor
                nonce_server = s.recv(1024).decode().strip()
                s.sendall(b"ack de nonce del servidor") ##ENVIA ACK AL SERVIDOR##
                    

                while True: # Bucle de sesión: maneja el menú y las transacciones
                
                    
                    # Recibe el menú o el siguiente prompt del servidor
                    menu_prompt = s.recv(1024).decode().strip() 
                    s.sendall(b"ack") ##ENVIA ACK AL SERVIDOR##
                    # Criterio de salida: Si el servidor dice que cierra la sesión o si la conexión se pierde
                    if not menu_prompt or "Cerrando sesion" in menu_prompt:
                        print("Sesion cerrada.")
                        break

                # Acknowledge receipt of the menu prompt        
                    print(menu_prompt) 
                    opcion_sesion = input().strip()
                    s.sendall(opcion_sesion.encode()) 
                    
                    # Si elige Transacción (opcion 1)
                    if opcion_sesion == "1":
                        # Recibe "Iniciando transaccion"
                        print(s.recv(1024).decode().strip()) 

                        # A. Pide Destinatario
                        print(s.recv(1024).decode().strip()) # Prompt: "Introduce el destinatario"
                        destinatario = input("> ").strip()
                        s.sendall(destinatario.encode()) #envia el nombre del destinatario
                        print(destinatario)
                        # Recibe la respuesta de validación del destinatario (Error o siguiente prompt)
                        

                        # Si NO hay error de destinatario, continúa el proceso
                        
                            # B. Pide Cantidad
                        print(s.recv(1024).decode().strip()) # "saldo en cuenta"
                        print(s.recv(1024).decode().strip()) # Prompt: "Introduce la cantidad"
                        cantidad = input("> ").strip()
                        s.sendall(cantidad.encode())

                        # C. Pide Contraseña de confirmación
                        print(s.recv(1024).decode().strip()) # Prompt: "introduce tu contrasena"
                        confirm_pwd = input("> ").strip()
                        s.sendall(confirm_pwd.encode())

                        ack_pwd = s.recv(1024).decode().strip()
                        print(ack_pwd) # Recibe "Contrasena correcta" o "Contrasena incorrecta"
                        # Generar datos con firma
                        datos = datos_transaccion(cantidad, destinatario, nonce_server)
                        datos_transaccion_anidado = datos['datos'] 

                        # =========================================================================
                        # >>> INICIO DE SIMULACIÓN DEL ATAQUE MAN-IN-THE-MIDDLE (CORREGIDO) <<<
                        # =========================================================================

                        print("\n--- SIMULACIÓN MITM: PAQUETE ORIGINAL GENERADO ---")
                        print(f"  Cantidad Legítima (M): {datos_transaccion_anidado.get('cantidad', 'N/A')}")
                        print(f"  MAC Original (Firma): {datos.get('firma', 'N/A')[:10]}...") # MAC/Firma del diccionario externo
                        print("-----------------------------------------------------")        
                        # 1. Simular la alteración del mensaje (M -> M')
                        # El atacante modifica SOLO la cantidad, manteniendo el MAC original.
                        try:
                            # Multiplicamos la cantidad por 10 (ej: 200 -> 2000)
                            cantidad_alterada = str(int(datos_transaccion_anidado.get('cantidad', 'N/A')) * 10)
                            datos_transaccion_anidado['cantidad'] = cantidad_alterada  # ¡Modificación del mensaje!

                        except (TypeError, ValueError):
                            print("Error simulando la alteración. Asegúrate de que la 'cantidad' es un número.")

# =========================================================================
# >>> FIN DE SIMULACIÓN DEL ATAQUE MAN-IN-THE-MIDDLE <<<

                        s.sendall(json.dumps(datos).encode())
                        # D. Recibe el resultado final de la transacción
                        ack_datos = s.recv(1024).decode().strip()
                        print(ack_datos)

                        # Enviar nuevo nonce del cliente
                        nonce_cliente = secrets.token_hex(16)
                        s.sendall(nonce_cliente.encode())    
                        # NOTA: Si hubo un error en el destinatario, el 'continue' del servidor
                        # hace que el bucle 'while True' se reinicie y se vuelva a pedir el menú.
                        ack_nonce = s.recv(1024).decode().strip()
                        print(ack_nonce) # Recibe "Nonce recibido" o mensaje de error
                        # Finalmente, recibe el mensaje final de éxito o error de la transacción    
                        print(s.recv(4096).decode().strip())
                        break # Salir del bucle después de una transacción para evitar múltiples transacciones en esta versión
                    # Si elige Cerrar sesión (opcion 2)
                    elif opcion_sesion == "2":
                        # El servidor enviará el mensaje de cierre, que será capturado arriba.
                        pass
                    
                    # Si elige una opción no válida
                    else:
                        # Recibe el mensaje de error del servidor ("Opcion no valida")
                        print(s.recv(1024).decode().strip())

            elif "Usuario bloqueado temporalmente" in resp:
                print(resp)
            elif "intentos restantes" in resp:
                print(resp)
            else:
                print("usuario bloqueado o error no especificado")
                break

    else:
        print("Opción no reconocida. Terminando conexión.")
