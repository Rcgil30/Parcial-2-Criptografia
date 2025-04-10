import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# ===============================================
# Funciones "placeholder" para ElGamal (sin cambios)
# ===============================================
def elgamal_keygen(params):
    priv = get_random_bytes(16)
    pub = get_random_bytes(16)
    return priv, pub

def elgamal_encrypt(plaintext, pub, params):
    ct = plaintext[::-1].encode()
    return ct

def elgamal_decrypt(ciphertext, priv, params):
    pt = ciphertext[::-1].decode()
    return pt

# ===============================================
# Carga de parámetros para ElGamal desde JSON
# ===============================================
with open('parameters.json', 'r') as f:
    params_data = json.load(f)
elgamal_params = params_data["parameters"][0]

# ===============================================
# Selección del modo de cifrado
# ===============================================
mode = input("Seleccione el modo de cifrado (1: RSA OAEP, 2: ElGamal): ").strip()

# Generación de claves y variable para almacenar la clave pública del cliente
if mode == "1":
    rsa_key = RSA.generate(2048)
    bob_private_key = rsa_key
    bob_public_key = rsa_key.publickey()
    client_rsa_public = None  # Se recibirá mediante handshake
elif mode == "2":
    bob_elgamal_privkey, bob_elgamal_pubkey = elgamal_keygen(elgamal_params)

# ===============================================
# Función para recibir mensajes
# ===============================================
def receive_messages(conn):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            # Descifrado de mensajes recibidos de Alice
            if mode == "1":
                cipher_rsa = PKCS1_OAEP.new(bob_private_key)
                plaintext = cipher_rsa.decrypt(data).decode()
                print(f"\nCliente: {plaintext}")
            elif mode == "2":
                plaintext = elgamal_decrypt(data, bob_elgamal_privkey, elgamal_params)
                print(f"\nCliente: {plaintext}")
            else:
                print(f"\nCliente (sin descifrar): {data}")
        except Exception as e:
            print("Error al descifrar:", e)
            break

# ===============================================
# Función para enviar mensajes
# ===============================================
def send_messages(conn):
    global client_rsa_public
    while True:
        message = input()
        if mode == "1":
            if client_rsa_public is None:
                print("Esperando la clave pública del cliente...")
                continue
            # Cifrado con la clave pública de Alice (cliente) para que solo ella pueda descifrar
            cipher_rsa = PKCS1_OAEP.new(client_rsa_public)
            ciphertext = cipher_rsa.encrypt(message.encode())
        elif mode == "2":
            ciphertext = elgamal_encrypt(message, b"dummy", elgamal_params)
        else:
            ciphertext = message.encode()
        print(f"Tamaño del mensaje cifrado: {len(ciphertext)} bytes")
        conn.sendall(ciphertext)

# ===============================================
# Inicialización del servidor y handshake
# ===============================================
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escuchando en {HOST}:{PORT}...")
    conn, addr = s.accept()
    print(f"Conectado por {addr}")
    
    # Proceso de handshake: recibir handshake inicial del cliente
    handshake_data = conn.recv(4096)
    if handshake_data.startswith(b"HANDSHAKE:"):
        parts = handshake_data.split(b'|', 1)
        handshake_info = parts[0].decode()
        client_keydata = parts[1]
        if "RSA" in handshake_info:
            # Se extrae y almacena la clave pública RSA del cliente para mensajes dirigidos a él
            client_rsa_public = RSA.import_key(client_keydata)
            # Se envía la clave pública de Bob para que el cliente pueda cifrar mensajes a Bob
            send_handshake = b"HANDSHAKE:MODE:RSA|" + bob_public_key.exportKey()
            conn.sendall(send_handshake)
        elif "ELGAMAL" in handshake_info:
            send_handshake = b"HANDSHAKE:MODE:ELGAMAL|" + bob_elgamal_pubkey
            conn.sendall(send_handshake)
    
    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()
    send_messages(conn)
