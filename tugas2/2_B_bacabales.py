#device b
#periksa folder, cari pesan A, baca n dekripsi pake private key B.
#B buat balesan, enkripsi pake public key A, kirim balesan ke folder A

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

print("\n[DEVICE B] Menerima dan membalas A")

#Baca pesan masuk
print("[B] Membaca file pesan_dari_A.dat")
with open("folder_B/pesan_dari_A.dat", "rb") as f:
    pesan_terenkripsi_A = f.read()

#B pake private key B
print("[B] Baca private key B (private_B.pem)")
with open("folder_B/private_B.pem", "rb") as key_file:
    private_key_B = serialization.load_pem_private_key(
        key_file.read(),
        password=None #tdk ada password di file key
    )

#B dekripsi pesan
print("[B] Dekripsi pesan menggunakan private_key_B")
try:
    pesan_terdekripsi_B = private_key_B.decrypt(
        pesan_terenkripsi_A,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[B] Pesan berhasil dibaca: {pesan_terdekripsi_B.decode()}")
except Exception as e:
    print(f"[B] GAGAL DEKRIPSI: {e}")

print("\n[B] Menyiapkan balasan untuk A")
#B buat balesan pesan
pesan_asli_B = b"Halo A, pesanmu udah takterima. Ini balasan rahasia dariku."
print(f"[B] Pesan balasan: {pesan_asli_B.decode()}")

#B baca public key A
print("[B] Baca public key A (public_A_dari_lawan.pem)")
with open("folder_B/public_A_dari_lawan.pem", "rb") as key_file:
    public_key_A = serialization.load_pem_public_key(key_file.read())

#B enkripsi balesan pake public key A
print("[B] Enkripsi balesan pake public_key_A")
pesan_terenkripsi_B = public_key_A.encrypt(
    pesan_asli_B,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#B kirim balesan terenkripsi ke folder A
print("[B] Kirim balesan ke folder_A/pesan_dari_B.dat")
with open("folder_A/pesan_dari_B.dat", "wb") as f:
    f.write(pesan_terenkripsi_B)

print("[DEVICE B] Pesan dibaca dan balesan terkirim")