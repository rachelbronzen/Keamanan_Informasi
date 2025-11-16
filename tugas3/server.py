#menggunakan threading untuk menangani banyak klien.

import socket
import threading
import pickle

HOST = '0.0.0.0'
PORT = 9999

#daftar klien terhubung
#format: clients[nama_client] = {'conn': obyek_koneksi, 'pubkey': public_key_rsa}
clients = {}
client_lock = threading.Lock() #amankan akses ke dict 'clients'

def handle_client(conn, addr): #jalanin di thread terpisah tiap client
    print(f"[SERVER] Klien baru terhubung dari {addr}")
    client_name = None
    try:
        #registrasi client
        reg_data = conn.recv(4096)
        reg_info = pickle.loads(reg_data)
        
        client_name = reg_info['name']
        client_pubkey = reg_info['pubkey']
        
        #simpen info klien
        with client_lock:
            clients[client_name] = {
                'conn': conn,
                'pubkey': client_pubkey
            }
        print(f"[SERVER] Klien '{client_name}' telah mendaftar dengan public key-nya.")

        #loop terima terusin pesan
        while True:
            data_mentah = conn.recv(4096)
            if not data_mentah:
                break
            
            message = pickle.loads(data_mentah)
            
            target_name = message['target']
            
            #ambil koneksi target dari daftar klien
            target_conn = None
            with client_lock:
                if target_name in clients:
                    target_conn = clients[target_name]['conn']
            
            if target_conn:
                print(f"[SERVER] Meneruskan pesan dari '{client_name}' ke '{target_name}'")
                #teruskan pesan format pickle ke target
                target_conn.sendall(data_mentah)
            else:
                print(f"[SERVER] GAGAL: Target '{target_name}' tidak ditemukan/terhubung.")

    except Exception as e:
        print(f"[SERVER] Error pada koneksi {addr}: {e}")
    finally:
        #bersihin pas klien putus
        if client_name:
            with client_lock:
                if client_name in clients:
                    del clients[client_name]
            print(f"[SERVER] Klien '{client_name}' terputus. Koneksi ditutup.")
        conn.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server mendengarkan di {HOST}:{PORT}...")

    while True:
        koneksi, alamat = server_socket.accept()
        #buat thread baru tangani klien
        thread = threading.Thread(target=handle_client, args=(koneksi, alamat))
        thread.daemon = True #thread mati pas program utama mati
        thread.start()

if __name__ == "__main__":
    start_server()