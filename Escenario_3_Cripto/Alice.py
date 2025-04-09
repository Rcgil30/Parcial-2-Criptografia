import socket
import threading
from crypto_utils import *

# === Configuración ===
MODE = "ElGamal"  # Cambiar a "RSA" si es necesario
PARAM_INDEX = 0    # Índice del grupo de parámetros en parameters.json

# Cargar parámetros y claves
if MODE == "RSA":
    client_private, client_public = generate_rsa_keys()
    server_public = RSA.import_key(open("bob_rsa_public.pem").read())  # Clave pública de Bob
elif MODE == "ElGamal":
    p, g = load_parameters(PARAM_INDEX)
    client_x, client_h = generate_elgamal_keys(p, g)
    server_h = int(open("bob_elgamal_public.txt").read())  # Clave pública de Bob

# === Funciones de comunicación ===
def receive_messages(sock):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            if MODE == "RSA":
                decrypted = decrypt_rsa(data, client_private)
            else:
                decrypted = decrypt_elgamal(data, client_x, p)
            print(f"\nBob: {decrypted}")
        except Exception as e:
            print(f"Error al descifrar: {e}")
            break

def send_messages(sock):
    while True:
        message = input()
        try:
            if MODE == "RSA":
                encrypted = encrypt_rsa(message, server_public)
            else:
                encrypted = encrypt_elgamal(message, server_h, p, g)
            sock.sendall(encrypted)
        except Exception as e:
            print(f"Error al cifrar: {e}")

# === Conexión ===
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Conectado a Bob.")
    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()
    send_messages(s)