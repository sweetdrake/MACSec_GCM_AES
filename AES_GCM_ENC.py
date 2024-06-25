# Gen code by chatgpt
# Refer to IEEE 802.1AE Table C-27
from Crypto.Util.strxor import strxor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import struct

def increment_counter(counter):
    """Increment the counter used in GCM mode."""
    counter_int = int.from_bytes(counter, byteorder='big') + 1
    return counter_int.to_bytes(16, byteorder='big')

def ghash(h, a, c):
    """Compute GHASH for GCM."""
    def mul_gf2(x, y):
        R = 0xE1000000000000000000000000000000
        z = 0
        v = x
        for i in range(128):
            if (y >> (127 - i)) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v >>= 1
        return z

    def to_int(b):
        return int.from_bytes(b, byteorder='big')

    def from_int(i):
        return i.to_bytes(16, byteorder='big')

    a_padded = a + b'\x00' * ((16 - len(a) % 16) % 16)
    c_padded = c + b'\x00' * ((16 - len(c) % 16) % 16)
    len_block = struct.pack('>QQ', len(a) * 8, len(c) * 8)

    x = 0
    for block in (a_padded[i:i + 16] for i in range(0, len(a_padded), 16)):
        x = mul_gf2(x ^ to_int(block), to_int(h))

    for block in (c_padded[i:i + 16] for i in range(0, len(c_padded), 16)):
        x = mul_gf2(x ^ to_int(block), to_int(h))

    x = mul_gf2(x ^ to_int(len_block), to_int(h))
    return from_int(x)

def encrypt_block(key, block):
    """Encrypt a single block using AES in ECB mode."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()

# Provided values
K = binascii.unhexlify('071B113B0CA743FECCCF3D051F737382')
P = binascii.unhexlify('08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340004')
A = binascii.unhexlify('E20106D7CD0DF0761E8DCD3D88E54C2A76D457ED')
IV = binascii.unhexlify('F0761E8DCD3D000176D457ED')

# Step 1: Generate the hash subkey (H)
H = encrypt_block(K, b'\x00' * 16)

# Step 2: Prepare the counter block (Y)
Y0 = IV + b'\x00\x00\x00\x01'
Y = Y0

# Step 3: Encrypt the plaintext
ciphertext = b''
for i in range(0, len(P), 16):
    Y = increment_counter(Y)
    encrypted_counter = encrypt_block(K, Y)
    block = P[i:i + 16]
    if len(block) < 16:
        block += b'\x00' * (16 - len(block))  # Pad block to 16 bytes
    encrypted_block = strxor(block, encrypted_counter)
    ciphertext += encrypted_block[:len(P[i:i + 16])]  # Remove padding if any

# Step 4: Compute GHASH
ghash_result = ghash(H, A, ciphertext)

# Step 5: Compute the authentication tag
T = strxor(ghash_result, encrypt_block(K, Y0))

# Output the results
print("Ciphertext (C):", binascii.hexlify(ciphertext).decode().upper())
print("Authentication Tag (T):", binascii.hexlify(T).decode().upper())
