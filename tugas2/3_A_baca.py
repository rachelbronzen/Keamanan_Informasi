#device A
#cek folder, menemukan balasan dari B, membaca, dekripsi pake private key A.

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

print("\n[DEVICE A] Terima balasan")

#baca file yang masuk
print("[A] Membaca file pesan_dari_B.dat")
with open("folder_A/pesan_dari_B.dat", "rb") as f:
    pesan_terenkripsi_B = f.read()

#pake private key A
print("[A] Membaca private key A (private_A.pem)")
with open("folder_A/private_A.pem", "rb") as key_file:
    private_key_A = serialization.load_pem_private_key(
        key_file.read(),
        password=None # Tidak ada password di file key
    )

#dekripsi balesan
print("[A] Dekripsi balasan menggunakan private_key_A")
try:
    pesan_terdekripsi_A = private_key_A.decrypt(
        pesan_terenkripsi_B,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[A] Balasan berhasil dibaca: {pesan_terdekripsi_A.decode()}")
except Exception as e:
    print(f"[A] GAGAL DEKRIPSI: {e}")

print("[DEVICE A] Simulasi komunikasi dua arah selesai")