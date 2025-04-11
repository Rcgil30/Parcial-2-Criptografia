import socket
import threading
import json
import random
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ===============================================
# Funciones para ElGamal
# ===============================================
def elgamal_keygen(params):
    p = params["p"]
    q = params["q"]
    g = params["g"]
    x = random.randint(2, q - 1)
    y = pow(g, x, p)
    return x, (p, g, y)

def elgamal_encrypt(message, pubkey, params):
    p, g, y = pubkey
    q = params["q"]
    m_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    if m_int >= p:
        raise ValueError("El mensaje es demasiado grande para el parámetro p actual.")
    k = random.randint(2, q - 1)
    a = pow(g, k, p)
    b = (m_int * pow(y, k, p)) % p
    ciphertext_str = f"{a}:{b}"
    return ciphertext_str.encode('utf-8')

def elgamal_decrypt(ciphertext, privkey, params):
    text = ciphertext.decode('utf-8')
    a_str, b_str = text.split(":")
    a = int(a_str)
    b = int(b_str)
    p = params["p"]
    s = pow(a, privkey, p)
    s_inv = pow(s, -1, p)
    m_int = (b * s_inv) % p
    m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')
    try:
        return m_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return "Error"

# ===============================================
# Carga de parámetros para ElGamal desde JSON
# ===============================================
with open('parameters.json', 'r') as f:
    params_data = json.load(f)
# Se selecciona el último conjunto de parámetros (con p grande)
elgamal_params = params_data["parameters"][-1]

# ===============================================
# Selección del modo de cifrado por parte del usuario
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
# Función para recibir mensajes (hilo receptor)
# ===============================================
def receive_messages(sock):
    global bob_public_key, bob_elgamal_pubkey
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            # Procesar handshake
            if data.startswith(b"HANDSHAKE:"):
                parts = data.split(b'|', 1)
                handshake_info = parts[0].decode()
                keydata = parts[1]
                if "RSA" in handshake_info:
                    bob_public_key = RSA.import_key(keydata)
                    print("Clave pública RSA del servidor recibida.")
                    sys.stdout.flush()
                elif "ELGAMAL" in handshake_info:
                    values = keydata.decode('utf-8').split(':')
                    bob_elgamal_pubkey = (int(values[0]), int(values[1]), int(values[2]))
                    print("Clave pública ElGamal del servidor recibida.")
                    sys.stdout.flush()
                continue

            # Procesar mensaje
            if mode == "1":
                cipher_rsa = PKCS1_OAEP.new(alice_private_key)
                plaintext = cipher_rsa.decrypt(data).decode()
                print(f"\nBob: {plaintext}")
                sys.stdout.flush()
            elif mode == "2":
                plaintext = elgamal_decrypt(data, alice_elgamal_privkey, elgamal_params)
                print(f"\nBob: {plaintext}")
                sys.stdout.flush()
            else:
                print(f"\nBob (sin descifrar): {data}")
                sys.stdout.flush()
        except Exception as e:
            print("Error al descifrar:", e)
            sys.stdout.flush()
            break

# ===============================================
# Función para enviar mensajes (hilo de envío)
# ===============================================
def send_messages(sock):
    while True:
        message = input()  # Esta llamada se ejecutará en un hilo aparte
        if mode == "1":
            if bob_public_key is None:
                print("Esperando la clave pública del servidor...")
                sys.stdout.flush()
                continue
            cipher_rsa = PKCS1_OAEP.new(bob_public_key)
            ciphertext = cipher_rsa.encrypt(message.encode())
        elif mode == "2":
            if bob_elgamal_pubkey is None:
                print("Esperando la clave pública ElGamal del servidor...")
                sys.stdout.flush()
                continue
            ciphertext = elgamal_encrypt(message, bob_elgamal_pubkey, elgamal_params)
        else:
            ciphertext = message.encode()
        print(f"Tamaño del mensaje cifrado: {len(ciphertext)} bytes")
        sys.stdout.flush()
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
        handshake_msg = b"HANDSHAKE:MODE:ELGAMAL|" + f"{alice_elgamal_pubkey[0]}:{alice_elgamal_pubkey[1]}:{alice_elgamal_pubkey[2]}".encode('utf-8')
    s.sendall(handshake_msg)
    print("Conectado al servidor.")
    sys.stdout.flush()

    # Iniciar hilos para envío y recepción
    thread_recv = threading.Thread(target=receive_messages, args=(s,), daemon=True)
    thread_send = threading.Thread(target=send_messages, args=(s,), daemon=True)
    
    thread_recv.start()
    thread_send.start()
    
    # Esperar a que alguno de los hilos finalice (por ejemplo, por cierre de conexión)
    thread_recv.join()
    thread_send.join()