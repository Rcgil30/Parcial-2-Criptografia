import socket
import threading
from crypto_utils import *

# === Configuración ===
MODE = "ElGamal"   # Cambiar a "RSA" si es necesario
PARAM_INDEX = 0    # Índice del grupo de parámetros en parameters.json

# Cargar parámetros y claves
if MODE == "RSA":
    server_private, server_public = generate_rsa_keys()
    client_public = RSA.import_key(open("alice_rsa_public.pem").read())  # Clave pública de Alice
elif MODE == "ElGamal":
    p, g = load_parameters(PARAM_INDEX)
    server_x, server_h = generate_elgamal_keys(p, g)
    client_h = int(open("alice_elgamal_public.txt").read())  # Clave pública de Alice

# === Funciones de comunicación ===
def receive_messages(conn):
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            if MODE == "RSA":
                decrypted = decrypt_rsa(data, server_private)
            else:
                decrypted = decrypt_elgamal(data, server_x, p)
            print(f"\nAlice: {decrypted}")
        except Exception as e:
            print(f"Error al descifrar: {e}")
            break

def send_messages(conn):
    while True:
        message = input()
        try:
            if MODE == "RSA":
                encrypted = encrypt_rsa(message, client_public)
            else:
                encrypted = encrypt_elgamal(message, client_h, p, g)
            conn.sendall(encrypted)
        except Exception as e:
            print(f"Error al cifrar: {e}")

# === Conexión ===
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Escuchando en {HOST}:{PORT}...")
    conn, addr = s.accept()
    print(f"Conectado por {addr}")
    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()
    send_messages(conn)