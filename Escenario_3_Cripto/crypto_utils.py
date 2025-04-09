from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import random

# Generación de claves RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Generación de parámetros y claves ElGamal
def generate_elgamal_params():
    p = getPrime(512)  # Primo de 512 bits
    g = 2              # Generador
    return p, g

def generate_elgamal_keys(p):
    x = random.randint(1, p-2)  # Clave privada
    h = pow(g, x, p)            # Clave pública
    return x, h

# Cifrado/Descifrado RSA-OAEP
def encrypt_rsa(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(message.encode())

def decrypt_rsa(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext).decode()

# Cifrado/Descifrado ElGamal
def encrypt_elgamal(message, h, p, g):
    m = bytes_to_long(message.encode())
    y = random.randint(1, p-2)
    c1 = pow(g, y, p)
    c2 = (m * pow(h, y, p)) % p
    return f"{c1},{c2}".encode()

def decrypt_elgamal(ciphertext, x, p):
    c1, c2 = map(int, ciphertext.decode().split(','))
    s = pow(c1, x, p)
    m = (c2 * pow(s, -1, p)) % p
    return long_to_bytes(m).decode()