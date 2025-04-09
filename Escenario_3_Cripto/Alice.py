import socket
import threading
from crypto_utils import *

# Configuración (RSA o ElGamal)
MODE = "ElGamal"  # Cambiar a "RSA" según sea necesario

# Generar claves según el modo
if MODE == "RSA":
    client_private, client_public = generate_rsa_keys()
    server_public = RSA.import_key(open("server_rsa_public.pem").read())  # Asumir clave precompartida
elif MODE == "ElGamal":
    p, g = generate_elgamal_params()
    client_x, client_h = generate_elgamal_keys(p)
    server_h = int(open("server_elgamal_public.txt").read())  # Asumir clave precompartida

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
            print(f"\nServidor: {decrypted}")
        except:
            break

def send_messages(sock):
    while True:
        message = input()
        if MODE == "RSA":
            encrypted = encrypt_rsa(message, server_public)
        else:
            encrypted = encrypt_elgamal(message, server_h, p, g)
        sock.sendall(encrypted)

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Conectado al servidor.")
    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()
    send_messages(s)