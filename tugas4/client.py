#!/usr/bin/env python3
import socket
import threading
import struct
import argparse
import sys
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

#signature
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from des import encrypt_cbc, decrypt_cbc


def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def send_framed(sock, payload_bytes):
    header = struct.pack('>I', len(payload_bytes))
    sock.sendall(header + payload_bytes)


def recv_framed(sock):
    header = recv_all(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('>I', header)
    return recv_all(sock, length)


#RSA helper
def rsa_encrypt(pubkey, data_bytes):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data_bytes)

def rsa_decrypt(privkey, enc_bytes):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(enc_bytes)

#signature
def rsa_sign(privkey, data_bytes):
    h = SHA256.new(data_bytes)
    return pkcs1_15.new(privkey).sign(h)

def rsa_verify(pubkey, data_bytes, signature):
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

#pubkey dan sessionkey
def send_public_key(sock, role, pubkey):
    msg = {
        "type": "PUBKEY",
        "role": role,
        "data": base64.b64encode(pubkey.export_key()).decode()
    }
    send_framed(sock, json.dumps(msg).encode())


def send_session_key(sock, role, enc_session_key):
    msg = {
        "type": "SESSIONKEY",
        "role": role,
        "data": base64.b64encode(enc_session_key).decode()
    }
    send_framed(sock, json.dumps(msg).encode())


def recv_loop(sock, des_key_box, rsa_priv):
    #terima pesan n verifikasi signature
    try:
        while True:
            raw = recv_framed(sock)
            if raw is None:
                print("\n[!] Server menutup koneksi.")
                break

            msg = json.loads(raw.decode())
            mtype = msg.get("type", "")

            #pubkey dari peer
            if mtype == "PUBKEY":
                print("\r[INFO] Menerima PUBKEY dari peer.\n[KAMU]: ", end="", flush=True)
                peer_pub_bytes = base64.b64decode(msg["data"])
                des_key_box["peer_public_key"] = RSA.import_key(peer_pub_bytes)
                continue

            #sessionkey terenkripsi
            if mtype == "SESSIONKEY":
                print("\r[INFO] Menerima SESSIONKEY terenkripsi...\n[KAMU]: ", end="", flush=True)
                enc = base64.b64decode(msg["data"])
                try:
                    des_key_box["key"] = rsa_decrypt(rsa_priv, enc)
                    print("\r[INFO] SESSION KEY DES didekripsi & disimpan.\n[KAMU]: ", end="", flush=True)
                except Exception as e:
                    print(f"\r[!] ERROR decrypt SESSIONKEY: {e}\n[KAMU]: ", end="", flush=True)
                continue

            #data terenkripsi (DES) + signature
            if mtype == "DATA":
                if des_key_box["key"] is None:
                    continue
                encrypted_payload = base64.b64decode(msg["data"])
                
                #ambil signature dari paket
                signature_b64 = msg.get("signature") 
                verification_status = ""

                try:
                    #decrypt DES
                    pt = decrypt_cbc(encrypted_payload, des_key_box["key"])
                    try:
                        text = pt.decode()
                    except:
                        text = pt.decode("latin1")
                    
                    #verifikasi signature RSA
                    if signature_b64 and des_key_box["peer_public_key"]:
                        sig_bytes = base64.b64decode(signature_b64)
                        if rsa_verify(des_key_box["peer_public_key"], text.encode(), sig_bytes):
                            verification_status = ""
                        else:
                            verification_status = "❌ [BAHAYA PESAN PALSU]"
                    
                    print(f"\r[PEER]: {text} {verification_status}\n[KAMU]: ", end="", flush=True)
                
                except Exception as e:
                    print(f"\r[!] Gagal decrypt DATA: {e}\n[KAMU]: ", end="", flush=True)
                continue

    except Exception as e:
        print("[!] Error recv_loop:", e)
    finally:
        sock.close()

def send_loop(sock, des_key_box, role, rsa_priv):
    try:
        while True:
            msg = input("[KAMU]: ")
            if not msg:
                continue

            if msg.strip().upper() == "QUIT":
                sys.exit(0)

            if des_key_box["key"] is None:
                print("[!] Belum ada session key, tunggu negotiation.")
                continue
            
            #buat signature
            signature = rsa_sign(rsa_priv, msg.encode())

            #enkripsi pesan
            encrypted = encrypt_cbc(msg.encode(), des_key_box["key"])
            
            #bungkus paket (pesan + signature)
            packet = {
                "type": "DATA",
                "role": role,
                "data": base64.b64encode(encrypted).decode(),
                "signature": base64.b64encode(signature).decode() # <--- PENTING!
            }
            send_framed(sock, json.dumps(packet).encode())

    except:
        pass
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=45000)
    parser.add_argument("--role", required=True, help="A atau B")
    parser.add_argument("--initiator", action="store_true",
                        help="Jika diset, client ini yang membuat DES session key")
    args = parser.parse_args()

    role = args.role.upper()
    if role not in ("A", "B"):
        print("role harus A atau B")
        sys.exit(1)

    #buat RSA key pair
    rsa_key = RSA.generate(2048)
    rsa_priv = rsa_key
    rsa_pub = rsa_key.publickey()

    print("[INFO] RSA keypair dibuat.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
        print("[+] Terhubung ke server.")
    except Exception as e:
        print(f"[!] Gagal connect ke {args.host}:{args.port}. Error: {e}")
        sys.exit(1)

    #container untuk session key DES
    des_key_box = {"key": None, "peer_public_key": None}

    #kirim pubkey ke server
    send_public_key(sock, role, rsa_pub)

    t = threading.Thread(target=recv_loop, args=(sock, des_key_box, rsa_priv), daemon=True)
    t.start()

    #negotiation (jika initiator)
    if args.initiator:
        print("[INITIATOR] Menunggu peer public key...")
        while des_key_box["peer_public_key"] is None:
            pass

        session_key = get_random_bytes(8)   # DES key
        des_key_box["key"] = session_key

        print("[INITIATOR] Membuat session key DES dan mengenkripsi dengan RSA peer...")
        enc = rsa_encrypt(des_key_box["peer_public_key"], session_key)

        send_session_key(sock, role, enc)
        print("[INITIATOR] Session key terkirim. Sekarang aman memakai DES.")

    else:
        print("[NON-INITIATOR] Menunggu SESSIONKEY dari peer...")

    #setelah negotiation, masuk mode chat
    send_loop(sock, des_key_box, role, rsa_priv)


if __name__ == "__main__":
    main()