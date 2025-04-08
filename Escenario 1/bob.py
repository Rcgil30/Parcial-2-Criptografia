import socket
import threading
import json
import random
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def receive_messages(sock, key):
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                break
            nonce = data[:8]
            data = data[8:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            data = cipher.decrypt(data).decode()
            print(f"Alice: {data}")
        except:
            break

def send_messages(sock, key):
    while True:
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        message = input()
        if message.lower() == 'salir':
            break
        message = cipher.encrypt(message.encode())
        sock.sendall(nonce + message)

def load_parameters():
    with open("parameters.json", "r") as file:
        data = json.load(file)
    scenarios = []
    for i, param_set in enumerate(data["parameters"], start=1):
        p = param_set["p"]
        q = param_set["q"]
        g = param_set["g"]
        
        # Create a dictionary for the scenario
        scenario = {
            "scenario": i,
            "p": p,
            "q": q,
            "g": g
        }
        scenarios.append(scenario)
    return scenarios

def generate_beta(q):
    return random.randint(0, q - 2)

HOST = '127.0.0.1'
PORT = 65432

def init_connection():
    parameters = load_parameters()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        conn, _ = s.accept()
        print("Conexión con Alice establecida.")
        
        scenario, u = conn.recv(1024).decode().split("|")
        u = int(u)

        num = int(scenario) - 1
        p, q, g = parameters[num]["p"], parameters[num]["q"], parameters[num]["g"]
        beta = generate_beta(q)
        v = pow(g, beta, p)
        conn.sendall(str(v).encode())

        w = pow(u, beta, p)
        key = HKDF(master=w.to_bytes(32, 'big'),key_len= 32, salt=b'', hashmod=SHA256)

        threading.Thread(target=receive_messages, args=(conn, key,), daemon=True).start()
        send_messages(conn, key)


if __name__ == "__main__":
    init_connection()