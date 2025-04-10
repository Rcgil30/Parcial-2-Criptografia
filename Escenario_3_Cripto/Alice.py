import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# ===============================================
# Funciones "placeholder" para ElGamal (no afectadas en este cambio)
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

# Variables globales para guardar claves del servidor
bob_public_key = None
bob_elgamal_pubkey = None

# Para RSA generamos el par de claves de Alice
if mode == "1":
    rsa_key_alice = RSA.generate(2048)
    alice_private_key = rsa_key_alice
    alice_public_key = rsa_key_alice.publickey()
elif mode == "2":
    alice_elgamal_privkey, alice_elgamal_pubkey = elgamal_keygen(elgamal_params)

# ===============================================
# Función para recibir mensajes
# ===============================================
def receive_messages(sock):
    global bob_public_key, bob_elgamal_pubkey
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            # Proceso de handshake: recibir la clave pública del servidor
            if data.startswith(b"HANDSHAKE:"):
                # Se espera el formato: "HANDSHAKE:MODE:RSA|<keydata>" o similar
                parts = data.split(b'|', 1)
                handshake_info = parts[0].decode()
                keydata = parts[1]
                if "RSA" in handshake_info:
                    bob_public_key = RSA.import_key(keydata)
                    print("Clave pública RSA del servidor recibida.")
                elif "ELGAMAL" in handshake_info:
                    bob_elgamal_pubkey = keydata  # Se debe deserializar apropiadamente en producción
                    print("Clave pública ElGamal del servidor recibida.")
                continue

            # Descifrado del mensaje en RSA: se utiliza la clave privada de Alice
            if mode == "1":
                cipher_rsa = PKCS1_OAEP.new(alice_private_key)
                plaintext = cipher_rsa.decrypt(data).decode()
                print(f"\nServidor: {plaintext}")
            elif mode == "2":
                plaintext = elgamal_decrypt(data, alice_elgamal_privkey, elgamal_params)
                print(f"\nServidor: {plaintext}")
            else:
                print(f"\nServidor (sin descifrar): {data}")
        except Exception as e:
            print("Error al descifrar:", e)
            break

# ===============================================
# Función para enviar mensajes
# ===============================================
def send_messages(sock):
    while True:
        message = input()
        if mode == "1":
            if bob_public_key is None:
                print("Esperando la clave pública del servidor...")
                continue
            # Encriptación con la clave pública de Bob para mensajes dirigidos al servidor
            cipher_rsa = PKCS1_OAEP.new(bob_public_key)
            ciphertext = cipher_rsa.encrypt(message.encode())
        elif mode == "2":
            if bob_elgamal_pubkey is None:
                print("Esperando la clave pública ElGamal del servidor...")
                continue
            ciphertext = elgamal_encrypt(message, bob_elgamal_pubkey, elgamal_params)
        else:
            ciphertext = message.encode()

        print(f"Tamaño del mensaje cifrado: {len(ciphertext)} bytes")
        sock.sendall(ciphertext)

# ===============================================
# Conexión y handshake inicial
# ===============================================
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # En handshake, para RSA se envía la clave pública de Alice
    if mode == "1":
        handshake_msg = b"HANDSHAKE:MODE:RSA|" + alice_public_key.exportKey()
    elif mode == "2":
        handshake_msg = b"HANDSHAKE:MODE:ELGAMAL|" + alice_elgamal_pubkey
    s.sendall(handshake_msg)
    print("Conectado al servidor.")

    threading.Thread(target=receive_messages, args=(s,), daemon=True).start()
    send_messages(s)
