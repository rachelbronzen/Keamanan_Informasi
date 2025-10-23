import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad

HOST = '127.0.0.1'
PORT = 9999

#membaca kunci rahasia bersama
with open("shared_key.key", "rb") as key_file:
    shared_key = key_file.read()

#membuat objek socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen() 

print(f"[SERVER] Mendengarkan di {HOST}:{PORT}")

#program berhenti ketika ada client yang terhubung
koneksi, alamat_client = server_socket.accept()
print(f"[SERVER] Terhubung dengan {alamat_client}")

#terima pesan dari client
try:
    #terima data mentah (bytes) dari client
    data_dari_A = koneksi.recv(1024) 
    
    iv_A = data_dari_A[:8] #ambil 8 byte pertama sbg IV
    ciphertext_A = data_dari_A[8:] # ambil sisa data

    #dekripsi pesan
    print("[SERVER] Mendekripsi pesan dari client")
    cipher_B_read = DES.new(shared_key, DES.MODE_CBC, iv=iv_A)
    pesan_terdekripsi = unpad(cipher_B_read.decrypt(ciphertext_A), DES.block_size)
    print(f"[SERVER] Pesan : {pesan_terdekripsi.decode()}")

    print("\n[SERVER] Mengirim balasan")
    pesan_balasan_B = b"Halooo, pesan DES mu via socket diterima!"

    #enkripsi balasan > buat IV baru, pad, encrypt
    print("[CLIENT] Enkripsi balasan")
    cipher_B_reply = DES.new(shared_key, DES.MODE_CBC)
    iv_B = cipher_B_reply.iv
    padded_balasan = pad(pesan_balasan_B, DES.block_size)
    balasan_terenkripsi = cipher_B_reply.encrypt(padded_balasan)

    print("[SERVER] Kirim balasan terenkripsi ke client")
    koneksi.sendall(iv_B + balasan_terenkripsi) #kirim IV + Ciphertext

except Exception as e:
    print(f"[SERVER] ERROR : {e}")

finally:
    koneksi.close()
    server_socket.close()
    print("[SERVER] Koneksi ditutup.")