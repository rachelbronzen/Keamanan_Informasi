#device a
#baca publik key b > buat pesan, enkripsi, kirim dgn cara simpen file terenkripsi di folder B

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
print("[DEVICE A] Kirim pesan ke B")

#pesan yang akan dikirim
pesan_asli_A = b"Halo B, ini ya pesan rahasia dari aku, A."
print(f"[A] Pesan asli: {pesan_asli_A.decode()}")

#A baca public key B yang udah diterima
print("[A] Baca public key B (public_B_dari_lawan.pem)")
with open("folder_A/public_B_dari_lawan.pem", "rb") as key_file:
    public_key_B = serialization.load_pem_public_key(key_file.read())

#A enkripsi pesan pake public key B
print("[A] Enkripsi pesan menggunakan public_key_B")
pesan_terenkripsi_A = public_key_B.encrypt(
    pesan_asli_A,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#A kirim pesan terenkripsi ke folder B
print("[A] Kirim pesan terenkripsi ke folder_B/pesan_dari_A.dat")
with open("folder_B/pesan_dari_A.dat", "wb") as f:
    f.write(pesan_terenkripsi_A)

print("[DEVICE A] Pesan telah terkirim")