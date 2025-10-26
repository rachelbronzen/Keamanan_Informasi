#A - terhubung IP Server

import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad

HOST = '192.168.1.24' #IP VM
PORT = 9999         

shared_key = b'\x1a\x8c\x3e\x0f\x9b\x22\x7d\x55' #kunci rahasia

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client_socket.connect((HOST, PORT))
    print(f"[CLIENT] Berhasil terhubung dengan server di {HOST}:{PORT}")

    pesan_asli_A = b"Halo Server B, ini pesan dari aku si Client A."
    
    #enkripsi pesan > buat IV baru, pad, encrypt
    print("[CLIENT] Mengenkripsi pesan")
    cipher_A = DES.new(shared_key, DES.MODE_CBC) 
    iv_A = cipher_A.iv
    padded_pesan = pad(pesan_asli_A, DES.block_size) #bantalan biar tetep kelipatan 8 byte.
    pesan_terenkripsi = cipher_A.encrypt(padded_pesan)

    print("[CLIENT] Mengirim pesan terenkripsi ke server")
    client_socket.sendall(iv_A + pesan_terenkripsi)

    print("\n[CLIENT] Menunggu balasan dari server")
    data_dari_B = client_socket.recv(1024) #terima data mentah smp 1024 bytes

    #IV n cipertext terpisah
    iv_B = data_dari_B[:8]
    ciphertext_B = data_dari_B[8:]

    print("[CLIENT] Mendekripsi balasan dari server")
    cipher_A_read = DES.new(shared_key, DES.MODE_CBC, iv=iv_B)
    balasan_terdekripsi = unpad(cipher_A_read.decrypt(ciphertext_B), DES.block_size)
    print(f"[CLIENT] Balasan dari Server B : {balasan_terdekripsi.decode()}")

except ConnectionRefusedError:
    print(f"[CLIENT] GAGAL: Koneksi ditolak. Pastikan:")
    print(f"    1. Server sudah berjalan di VM ({HOST}).")
    print(f"    2. Firewall di VM sudah mengizinkan port {PORT}.")
except Exception as e:
    print(f"[CLIENT] ERROR : {e}")

finally:
    client_socket.close() 
    print("[CLIENT] Koneksi ditutup.")