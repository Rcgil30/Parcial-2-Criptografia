from crypto_utils import *

# Generar claves ElGamal para Alice y Bob
def generate_elgamal_keys_for_both():
    p, g = load_parameters(index=0)
    
    # Claves de Alice
    alice_x, alice_h = generate_elgamal_keys(p, g)
    with open("alice_elgamal_public.txt", "w") as f:
        f.write(str(alice_h))
    
    # Claves de Bob
    bob_x, bob_h = generate_elgamal_keys(p, g)
    with open("bob_elgamal_public.txt", "w") as f:
        f.write(str(bob_h))

# Generar claves RSA para Alice y Bob
def generate_rsa_keys_for_both():
    # Claves de Alice
    alice_private, alice_public = generate_rsa_keys()
    with open("alice_rsa_public.pem", "wb") as f:
        f.write(alice_public)
    
    # Claves de Bob
    bob_private, bob_public = generate_rsa_keys()
    with open("bob_rsa_public.pem", "wb") as f:
        f.write(bob_public)

if __name__ == "__main__":
    generate_elgamal_keys_for_both()  # Comenta/descomenta según el modo
    # generate_rsa_keys_for_both()