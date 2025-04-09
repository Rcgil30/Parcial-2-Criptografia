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

HOST_ALICE = os.getenv("HOST_ALICE", "localhost")
PORT_ALICE = int(os.getenv("PORT_ALICE", 5000))
HOST_BOB = os.getenv("HOST_BOB", "localhost")
PORT_BOB = int(os.getenv("PORT_BOB", 6000))

def forward_messages(sock1, sock2, name, key1, key2):
    while True:
        try:
            data = sock1.recv(1024)
            if not data:
                break
            iv = data[:16]
            ciphertext = data[16:]
            message = decrypt_message(ciphertext, key1, iv)
            print(f"\n{name}: {message}")
            changeMessage = input("Escribe un nuevo mensaje para cambiarlo, de lo contrario ingresa enter: ")
            if changeMessage != "":
                message = changeMessage
            message = encrypt_message(message, key2)
            sock2.sendall(message)
        except:
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_alice:
        s_alice.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s_alice.bind((HOST_ALICE, PORT_ALICE))
        s_alice.listen()
        c_alice, _ = s_alice.accept()
        sk1, pk1 = generate_keys()
        data = c_alice.recv(1024)
        alice_pk = ECC.import_key(data)
        c_alice.sendall(pk1.export_key(format='DER'))
        shared_key_alice = derive_shared_key(sk1, alice_pk)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_bob:
            s_bob.connect((HOST_BOB, PORT_BOB))
            sk2, pk2 = generate_keys()
            s_bob.sendall(pk2.export_key(format='DER'))
            data = s_bob.recv(1024)
            bob_pk = ECC.import_key(data)
            shared_key_bob = derive_shared_key(sk2, bob_pk)

            threading.Thread(target=forward_messages, args=(c_alice, s_bob, "Alice", shared_key_alice, shared_key_bob), daemon=True).start()
            forward_messages(s_bob, c_alice, "Bob", shared_key_bob, shared_key_alice)

if __name__ == "__main__":
    init_connection()