from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20

alpha = 99 
v = 122
w = pow(122, alpha, 227)

key = HKDF(master=w.to_bytes(32, 'big'),key_len= 32, salt=b'', hashmod=SHA256)
data = b"\x94\xd1\x05\xaa\xef\x19}\xab\xe8\x7f#\xbb"
nonce, ciphertext = data[:8], data[8:]
cipher = ChaCha20.new(key=key, nonce=nonce)
plaintext = cipher.decrypt(ciphertext).decode()
print(plaintext)
