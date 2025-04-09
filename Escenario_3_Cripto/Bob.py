import socket
import threading
from crypto_utils import *

# Configuración (RSA o ElGamal)
MODE = "ElGamal"  # Cambiar a "RSA" según sea necesario

# Generar claves según el modo
if MODE == "RSA":
    server_private, server_public = generate_rsa_keys()
    client_public = RSA.import_key(open("client_rsa_public.pem").read())  # Asumir clave precompartida
elif MODE == "ElGamal":
    p, g = generate_elgamal_params()
    server_x, server_h = generate_elgamal_keys(p)
    client_h = int(open("client_elgamal_public.txt").read())  # Asumir clave precompartida

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
            print(f"\nCliente: {decrypted}")
        except:
            break

def send_messages(conn):
    while True:
        message = input()
        if MODE == "RSA":
            encrypted = encrypt_rsa(message, client_public)
        else:
            encrypted = encrypt_elgamal(message, client_h, p, g)
        conn.sendall(encrypted)

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escuchando en {HOST}:{PORT}...")
    conn, addr = s.accept()
    print(f"Conectado por {addr}")
    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()
    send_messages(conn)