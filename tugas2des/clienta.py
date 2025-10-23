import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad, pad

HOST = '127.0.0.1'
PORT = 9999 

#membaca kunci rahasia bersama
with open("shared_key.key", "rb") as key_file:
    shared_key = key_file.read()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    #menghubungi alamat & port server
    client_socket.connect((HOST, PORT))
    print(f"[CLIENT] Berhasil terhubung Server di {HOST}:{PORT}")

    #kirim pesan ke B
    pesan_asli_A = b"Halo bro, ini tes kirim pesan DES pake Socket."
    print(f"[CLIENT] Pesan asli: {pesan_asli_A.decode()}")
    
    #enkripsi balasan > buat IV baru, pad, encrypt
    print("[CLIENT] Enkripsi pesan")
    cipher_A = DES.new(shared_key, DES.MODE_CBC) 
    iv_A = cipher_A.iv
    padded_pesan = pad(pesan_asli_A, DES.block_size)
    pesan_terenkripsi = cipher_A.encrypt(padded_pesan)

    print("[CLIENT] Mengirim pesan terenkripsi ke B")
    client_socket.sendall(iv_A + pesan_terenkripsi) #kirim IV + Ciphertext ke server

    print("\n[CLIENT] Menunggu balasan dari B")
    data_dari_B = client_socket.recv(1024) #berhenti sampe server kirim balasan

    #IV dan ciphertext terpisah
    iv_B = data_dari_B[:8]
    ciphertext_B = data_dari_B[8:]

    print("[CLIENT] Mendekripsi balasan dari B")
    cipher_A_read = DES.new(shared_key, DES.MODE_CBC, iv=iv_B)
    balasan_terdekripsi = unpad(cipher_A_read.decrypt(ciphertext_B), DES.block_size)
    print(f"[CLIENT] Balasan dari B: {balasan_terdekripsi.decode()}")

except ConnectionRefusedError:
    print(f"[CLIENT] GAGAL!") #kl server blm jln
except Exception as e:
    print(f"[CLIENT] ERROR : {e}")

finally:
    client_socket.close()
    print("[CLIENT] Koneksi ditutup.")