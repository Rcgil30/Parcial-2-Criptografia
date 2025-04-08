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
            print(f"Bob: {data}")
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

def generate_alpha(q):
    return random.randint(0, q - 2)

HOST = '127.0.0.1'
PORT = 65432

def init_connection():
    scenario = input("Elige el escenario (1-5): ")
    while scenario not in ['1', '2', '3', '4', '5']:
        print("Escenario no válido. Por favor, elige un número entre 1 y 5.")
        scenario = input("Elige el escenario (1-5): ")
    parameters = load_parameters()
    num = int(scenario) - 1
    p, q, g = parameters[num]["p"], parameters[num]["q"], parameters[num]["g"]
    alpha = generate_alpha(q)
    u = pow(g, alpha, p)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Conexión con Bob establecida.")
        s.sendall(f"{scenario}|{u}".encode())
        v = int(s.recv(1024).decode())
        w = pow(v, alpha, p)
        key = HKDF(master=w.to_bytes(32, 'big'),key_len= 32, salt=b'', hashmod=SHA256)


        threading.Thread(target=receive_messages, args=(s, key,), daemon=True).start()
        send_messages(s, key)


if __name__ == "__main__":
    init_connection()