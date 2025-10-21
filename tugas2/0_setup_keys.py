#buat folder a dan b. key pair a disimpen di folder a dan key pair b disimpen di folder b.
#simulasi pertukaran public key > salin file public key antar folder

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import shutil

#buat folder A n B
os.makedirs("folder_A", exist_ok=True)
os.makedirs("folder_B", exist_ok=True)
print("Folder telah dibuat")

#buat key pair untuk A
print("Buat kunci untuk device A")
private_key_A = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_A = private_key_A.public_key()

#simpan key pair A ke folder_A - private key
with open("folder_A/private_A.pem", "wb") as f:
    f.write(private_key_A.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
#simpan public key A utk dibagikan
with open("folder_A/public_A.pem", "wb") as f:
    f.write(public_key_A.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

#buat key pair untuk B
print("[SETUP] Membuat kunci untuk Device B")
private_key_B = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_B = private_key_B.public_key()

#simpan key pair B ke folder_B - private key
with open("folder_B/private_B.pem", "wb") as f:
    f.write(private_key_B.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

#simpan public key B
with open("folder_B/public_B.pem", "wb") as f:
    f.write(public_key_B.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

#pertukaran public key
print("[SETUP] Mensimulasikan pertukaran public key")
shutil.copy("folder_A/public_A.pem", "folder_B/public_A_dari_lawan.pem") #A ke B
shutil.copy("folder_B/public_B.pem", "folder_A/public_B_dari_lawan.pem") #B ke A

print("Selesai! Kunci sudah dibuat dan didistribusikan")