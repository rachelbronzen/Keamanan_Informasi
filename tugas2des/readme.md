# Simulasi Komunikasi Dua Arah Dengan Algoritma DES dan Socket TCP

Koneksi dilakukan dengan Device A menggunakan windows dan Device B menggunakan Ubuntu.
Berikut yang dapat dilakukan saat mengatur VM Ubuntu:
1. Atur setting VM di network menjadi Bridged Adapter
2. Install python & pycryptodome
```
sudo apt update
sudo apt install python3 python3-pip
pip3 install pycryptodome
```
3. Melihat IP adress server Device B dengan melihat pada bagian inet (biasa dimulai dengan 192.x.x.x atau 10.x.x.x)
```
ip addr
```
4. Menyalin IP tersebut ke file client
5. Memasukkan perintah untuk izinkan port 9999 di terminal VM
```
sudo ufw allow 9999/tcp
```
6. Menjalankan file server lalu client.
```
python3 serverb.py
```


