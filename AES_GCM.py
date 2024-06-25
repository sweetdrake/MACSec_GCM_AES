# Gen code by chatgpt
# Refer to IEEE 802.1AE Table C-9
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

def gf_mult(x, y):
    R = 0xe1 << 120
    z = 0
    v = int.from_bytes(x, byteorder='big')
    w = int.from_bytes(y, byteorder='big')
    for i in range(128):
        if (w >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z.to_bytes(16, byteorder='big')

# Function to pad data to 16-byte blocks
def pad_to_16(data):
    if len(data) % 16 != 0:
        return data + b'\x00' * (16 - len(data) % 16)
    return data
# Key used for AES-128
key = bytes.fromhex('071B113B0CA743FECCCF3D051F737382')
cipher = AES.new(key, AES.MODE_ECB)

#1. Encrypt the Initial Counter Block:
#1-1 Encrypt an all-zero block with given key for deriving H
zero_block = b'\x00' * 16
H = cipher.encrypt(zero_block)
print(f"H: {H.hex().upper()}")
#1-2 With initial counter block(Y0) formed from IV, produce E(K, Y0)
Y0 = bytes.fromhex('F0761E8DCD3D000176D457ED00000001')
print(f"Y[0]): {Y0.hex().upper()}")
E_Y0 = cipher.encrypt(Y0)
print(f"E(K, Y[0]): {E_Y0.hex().upper()}")

#2. Compute GHASH
#2-1 Plain text(Additional authenticated data) in MACsec example
A = bytes.fromhex('E20106D7CD0DF0761E8DCD3D88E5400076D457ED08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0003')
len_A = (len(A) * 8).to_bytes(8, byteorder='big') # Lengths of A
A_padded = pad_to_16(A)
concatenated_data = A_padded + len_A
#####DEBUG#####
# hex_array = ''.join([hex(byte)[2:].zfill(2) for byte in concatenated_data])
# print(hex_array.upper())
###############

#2-2 Split concatenated data into 16-byte blocks
blocks = [concatenated_data[i:i+16] for i in range(0, len(concatenated_data), 16)]
if len(blocks[-1]) < 16:
    blocks[-1] = blocks[-1] + b'\x00' * (16 - len(blocks[-1]))

#2-3 Compute GHASH
X = [b'\x00' * 16]# Initialize X[0] to zero
for i, block in enumerate(blocks): # Compute X[i]
    temp = strxor(X[i], block)
    X.append(gf_mult(temp, H))
    print(f"X[{i}]: {X[i].hex().upper()}")
GHASH = X[-1] # Final GHASH value
print("GHASH(H,A,C):", GHASH.hex().upper())

#3 Combine GHASH and Encryption, for autentication tag T, T= E(K,Y0) ⊕ GHASH(H,A,C)
T = strxor(E_Y0, GHASH)
print("Authentication Tag (T):", T.hex().upper())
