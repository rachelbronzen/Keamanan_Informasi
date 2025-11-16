#jalanin Client A & Client C

import socket
import threading
import pickle
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = '10.149.120.220' #IP server VM
PORT = 9999

my_rsa_private_key = None
my_rsa_public_key = None
shared_des_key = None
des_key_lock = threading.Lock() #mengakses shared_des_key satu"

def send_pickled(sock, data_dict):
    sock.sendall(pickle.dumps(data_dict)) #kirim data dgn pickle

def encrypt_des(plain_text, key):
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(plain_text, DES.block_size)
    encrypted_msg = cipher.encrypt(padded_data)
    return iv + encrypted_msg

def decrypt_des(ciphertext_with_iv, key):
    iv = ciphertext_with_iv[:8]
    ciphertext = ciphertext_with_iv[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_data.decode()

#fungsi thread buat terima pesan
def receive_messages(sock, my_name, target_name):
    global shared_des_key
    while True:
        try:
            data_mentah = sock.recv(4096)
            if not data_mentah:
                print("[CLIENT] Koneksi server terputus.")
                break
            
            message = pickle.loads(data_mentah) #ubah data bytes (dr pickle) ke dict
            msg_type = message.get('type')
            
            #1 client C diminta A buat share public key RSA dari C
            if msg_type == 'get_key_request':
                print(f"[CLIENT] Menerima permintaan public key dari '{message['from']}'.")
                response = {
                    'type': 'key_response',
                    'target': message['from'],
                    'payload': my_rsa_public_key.export_key()
                }
                send_pickled(sock, response)
                print(f"[CLIENT] Public key RSA saya dikirim ke '{message['from']}'.")

            #2 balesan public key dari c 
            elif msg_type == 'key_response':
                print(f"[CLIENT] Menerima public key RSA dari '{target_name}'.")
                target_pubkey_pem = message['payload'] #ambil public key C
                target_pubkey = RSA.import_key(target_pubkey_pem) #ubah teks ke pubkey RSA
    
                new_des_key = get_random_bytes(8)
                
                #enkripsi kunci DES public key target C
                cipher_rsa = PKCS1_OAEP.new(target_pubkey) #ambil pengunci RSA, masukkan public key c 
                encrypted_des_key = cipher_rsa.encrypt(new_des_key) #ambil kunci DES dgn public key C
                
                print("[CLIENT] Kunci DES rahasia dibuat.")
                print("[CLIENT] Mengenkripsi kunci DES dengan public key C...")
                
                #kirim kunci DES terenkripsi ke C
                key_offer = {
                    'type': 'key_offer',
                    'target': target_name,
                    'payload': encrypted_des_key
                }
                send_pickled(sock, key_offer)
                print(f"[CLIENT] Kunci DES terenkripsi dikirim ke '{target_name}'.")

                #simpen kunci DES utk digunakan
                with des_key_lock:
                    shared_des_key = new_des_key
                print("--- Fase Pertukaran Kunci Selesai ---")

            #3 Terima tawaran kunci DES dari A
            elif msg_type == 'key_offer':
                #client C terima tawaran kunci DES dr A
                print(f"[CLIENT] Menerima tawaran kunci DES terenkripsi dari '{target_name}'.")
                encrypted_des_key = message['payload'] #ambil kunci
                
                #dekripsi dgn private key RSA yg udh ada
                cipher_rsa = PKCS1_OAEP.new(my_rsa_private_key)
                try:
                    new_des_key = cipher_rsa.decrypt(encrypted_des_key)
                    
                    #simpen kunci DES utk dipake
                    with des_key_lock:
                        shared_des_key = new_des_key
                    print("[CLIENT] Berhasil mendekripsi kunci DES.")
                    print("--- Fase Pertukaran Kunci Selesai ---")
                except ValueError as e:
                    print(f"[CLIENT] GAGAL mendekripsi kunci DES! {e}")
            
            #4 Penanganan Chat (habis kunci DES ada)
            elif msg_type == 'chat':
                print(f"\n[CLIENT] Menerima pesan chat terenkripsi...")
                with des_key_lock:
                    if shared_des_key:
                        try:
                            pesan_terdekripsi = decrypt_des(message['payload'], shared_des_key) #dekripsi pesan
                            print(f"\n[{target_name}]: {pesan_terdekripsi}")
                        except Exception as e:
                            print(f"[CLIENT] Gagal mendekripsi pesan: {e}")
                    else:
                        print("[CLIENT] Menerima pesan chat, tapi kunci DES belum ada.")

        except EOFError:
            break
        except Exception as e:
            print(f"[CLIENT] Error saat menerima data: {e}")
            break

def start_client():
    global my_rsa_private_key, my_rsa_public_key, shared_des_key
    
    print("[CLIENT] Membuat pasangan kunci RSA (2048 bit)...")
    key = RSA.generate(2048)
    my_rsa_private_key = key
    my_rsa_public_key = key.publickey()
    print("[CLIENT] Kunci RSA selesai dibuat.")
    
    my_name = input("Masukkan nama Anda (A atau C): ").strip().upper()
    if my_name not in ['A', 'C']:
        print("Nama harus 'A' atau 'C'.")
        return
    target_name = 'C' if my_name == 'A' else 'A'
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
        print(f"[CLIENT] Berhasil terhubung ke server di {HOST}:{PORT}")
    except Exception as e:
        print(f"[CLIENT] GAGAL terhubung ke server: {e}")
        return

    #registrasi ke server
    reg_info = {
        'name': my_name,
        'pubkey': my_rsa_public_key.export_key()
    }
    send_pickled(client_socket, reg_info)
    print(f"[CLIENT] Registrasi sebagai '{my_name}' dan mengirim public key ke server.")

    #jalanin thread untuk menerima pesan
    recv_thread = threading.Thread(target=receive_messages, args=(client_socket, my_name, target_name), daemon=True)
    recv_thread.start()

    #Mulai tuker kunci
    if my_name == 'A':
        print("\n[CLIENT] Menunggu 2 detik agar C siap...")
        time.sleep(2) 
        print(f"[CLIENT] Meminta public key '{target_name}' dari server...")
        #A mulai minta public key C
        request = {
            'type': 'get_key_request',
            'target': target_name,
            'from': my_name
        }
        send_pickled(client_socket, request)
    else:
        #output client C
        print(f"\n[CLIENT] Menunggu '{target_name}' memulai pertukaran kunci...")

    #loop kirim chat
    print("\n--- Mulai Sesi Chat ---")
    print("Ketik pesan Anda dan tekan Enter untuk mengirim.")
    print("Pesan TIDAK akan terkirim jika pertukaran kunci belum selesai.")
    
    try:
        while True:
            msg_text = input(f"[{my_name} -> {target_name}]: ")
            if msg_text.lower() == 'exit':
                break
                
            with des_key_lock:
                if shared_des_key:
                    #enkripsi
                    encrypted_payload = encrypt_des(msg_text.encode(), shared_des_key)
                    
                    #kirim pesan
                    chat_message = {
                        'type': 'chat',
                        'target': target_name,
                        'payload': encrypted_payload
                    }
                    send_pickled(client_socket, chat_message)
                else:
                    print("[CLIENT] Tunggu! Kunci DES belum disepakati. Pesan tidak terkirim.")
                    
    except KeyboardInterrupt:
        print("\n[CLIENT] Menutup koneksi...")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()