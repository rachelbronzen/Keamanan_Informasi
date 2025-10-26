#B - mendengarkan semua jaringan 

import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad

HOST = '0.0.0.0'  
PORT = 9999         

shared_key = b'\x1a\x8c\x3e\x0f\x9b\x22\x7d\x55'

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen() 

print("Menunggu koneksi dari client!")
koneksi, alamat_client = server_socket.accept()
print(f"[SERVER] Terhubung dengan {alamat_client}")

try:
    data_dari_A = koneksi.recv(1024) #terima data mentah smp 1024 bytes
    
    iv_A = data_dari_A[:8]
    ciphertext_A = data_dari_A[8:]

    print("[SERVER] Mendekripsi pesan dari client")
    cipher_B_read = DES.new(shared_key, DES.MODE_CBC, iv=iv_A)
    pesan_terdekripsi = unpad(cipher_B_read.decrypt(ciphertext_A), DES.block_size)
    print(f"[SERVER] Pesan dari client: {pesan_terdekripsi.decode()}")

    print("\n[SERVER] Menyiapkan balasan")
    pesan_balasan_B = b"Halo A, pesanmu aku terima. Salam kenal, aku B!!"
    
    #enkripsi pesan > buat IV baru, pad, encrypt
    cipher_B_reply = DES.new(shared_key, DES.MODE_CBC)
    iv_B = cipher_B_reply.iv
    padded_balasan = pad(pesan_balasan_B, DES.block_size) #bantalan biar tetep kelipatan 8 byte.
    balasan_terenkripsi = cipher_B_reply.encrypt(padded_balasan)

    print("[SERVER] Mengirim balasan terenkripsi ke client")
    koneksi.sendall(iv_B + balasan_terenkripsi)

except Exception as e:
    print(f"[SERVER] ERROR: {e}")

finally:
    koneksi.close() 
    server_socket.close() 
    print("[SERVER] Koneksi ditutup.")