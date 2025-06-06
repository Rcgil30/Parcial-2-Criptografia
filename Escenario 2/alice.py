import socket
import threading
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv("HOST_ALICE", "localhost")
PORT = int(os.getenv("PORT_ALICE", 5000))

def receive_messages(sock, key):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            iv = data[:16]
            ciphertext = data[16:]
            message = decrypt_message(ciphertext, key, iv)
            if message == "salir":
                break
            print(f"Bob: {message}")
        except:
            break

def send_messages(sock, key):
    while True:
        message = input()
        message = encrypt_message(message, key)
    
        sock.sendall(message)
        if message == "salir":
            break

def encrypt_message(message, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return iv + ct_bytes

def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode()

def generate_keys():
    sk = ECC.generate(curve='P-256')
    pk = sk.public_key()
    return sk, pk

def derive_shared_key(private_key, public_key):
    shared_point = public_key.pointQ * private_key.d
    shared_secret = int(shared_point.x).to_bytes(32, byteorder='big')
    derived_key = HKDF(shared_secret, 24, b'', SHA256)
    return derived_key

def init_connection():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Conexión establecida con Bob.")
        sk, pk = generate_keys()
        s.sendall(pk.export_key(format='DER'))
        bob_pk = ECC.import_key(s.recv(1024))
        shared_key = derive_shared_key(sk, bob_pk)

        threading.Thread(target=receive_messages, args=(s, shared_key,), daemon=True).start()
        send_messages(s, shared_key)

if __name__ == "__main__":
    init_connection()