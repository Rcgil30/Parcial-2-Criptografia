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
        return ""

# ===============================================
# Carga de parámetros para ElGamal desde JSON
# ===============================================
with open('parameters.json', 'r') as f:
    params_data = json.load(f)
# Se selecciona el último conjunto de parámetros (con p grande)
elgamal_params = params_data["parameters"][-1]

# ===============================================
# Selección del modo de cifrado
# ===============================================
mode = input("Seleccione el modo de cifrado (1: RSA OAEP, 2: ElGamal): ").strip()

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
            if mode == "1":
                cipher_rsa = PKCS1_OAEP.new(bob_private_key)
                plaintext = cipher_rsa.decrypt(data).decode()
                print(f"\nAlice: {plaintext}")
                sys.stdout.flush()
            elif mode == "2":
                plaintext = elgamal_decrypt(data, bob_elgamal_privkey, elgamal_params)
                print(f"\nAlice: {plaintext}")
                sys.stdout.flush()
            else:
                print(f"\nAlice (sin descifrar): {data}")
                sys.stdout.flush()
        except Exception as e:
            print("Error al descifrar:", e)
            sys.stdout.flush()
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
                sys.stdout.flush()
                continue
            cipher_rsa = PKCS1_OAEP.new(client_rsa_public)
            ciphertext = cipher_rsa.encrypt(message.encode())
        elif mode == "2":
            ciphertext = elgamal_encrypt(message, bob_elgamal_pubkey, elgamal_params)
        else:
            ciphertext = message.encode()
        print(f"Tamaño del mensaje cifrado: {len(ciphertext)} bytes")
        sys.stdout.flush()
        conn.sendall(ciphertext)

# ===============================================
# Inicialización del servidor y handshake
# ===============================================
HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escuchando en {HOST}:{PORT}...")
    sys.stdout.flush()
    conn, addr = s.accept()
    print(f"Conectado por {addr}")
    sys.stdout.flush()
    
    # Handshake: recibir handshake inicial del cliente
    handshake_data = conn.recv(4096)
    if handshake_data.startswith(b"HANDSHAKE:"):
        parts = handshake_data.split(b'|', 1)
        handshake_info = parts[0].decode()
        client_keydata = parts[1]
        if "RSA" in handshake_info:
            client_rsa_public = RSA.import_key(client_keydata)
            send_handshake = b"HANDSHAKE:MODE:RSA|" + bob_public_key.exportKey()
            conn.sendall(send_handshake)
        elif "ELGAMAL" in handshake_info:
            values = client_keydata.decode('utf-8').split(':')
            client_elgamal_pubkey = (int(values[0]), int(values[1]), int(values[2]))
            send_handshake = b"HANDSHAKE:MODE:ELGAMAL|" + f"{bob_elgamal_pubkey[0]}:{bob_elgamal_pubkey[1]}:{bob_elgamal_pubkey[2]}".encode('utf-8')
            conn.sendall(send_handshake)
    
    thread_recv = threading.Thread(target=receive_messages, args=(conn,), daemon=True)
    thread_send = threading.Thread(target=send_messages, args=(conn,), daemon=True)
    
    thread_recv.start()
    thread_send.start()
    
    thread_recv.join()
    thread_send.join()