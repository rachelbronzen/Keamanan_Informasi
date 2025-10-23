from Crypto.Random import get_random_bytes
import os

#panjang 8 byte (64 bit)
key = get_random_bytes(8)
filename = "shared_key.key"
with open(filename, "wb") as f:
    f.write(key)