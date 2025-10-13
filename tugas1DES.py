#didefinisikan standar DES
#initial permutation - ngacak urutan bit dari data 
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

#final permutation - akhir proses kembaliin urutan bit 
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

#expansion table - perluas data dari 32 bit jadi 48 (caranya diduplikasi)
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

#permutation function - di akhir setiap putaran utk acak hasil S box
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

#key permutation - ambil kunci 64 bit, buang 8 bit yg ga kepake, jadi 56
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

#key permutation - ambil kunci 56 bit yg udh digeser/rotate dan pilih 48 bit utk jd kunci
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

#substitution boxes - ambil 6 bit input n ganti jd 4 bit 
S_BOX = [
    #S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    #S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    #S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    #S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    #S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    #S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    #S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    #S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

#ubah heksadesimal (basis 16) ke biner (2)
#zfill mastiin hasil selalu 64 bit dgn tambah 0 di depan
def hex_to_bin(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(64)

#ubah biner ke heksadesimal buat tampilin hasil enkrip
def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].zfill(16)

#ubah teks ke biner 
def text_to_bin(text):
    return ''.join(format(ord(c), '08b') for c in text)

#ubah biner ke teks
def bin_to_text(bin_str):
    text = ""
    for i in range(0, len(bin_str), 8):
        text += chr(int(bin_str[i:i+8], 2))
    return text

#permutasi sesuai tabel - ambil biner k & atur ulang bit sesuai urutan di tabel
def permute(k, table):
    return "".join(k[p-1] for p in table)

#operasi XOR buat 2 string biner
def xor(a, b):
    return "".join('1' if x != y else '0' for x, y in zip(a, b))

#geser bit ke kiri (rotasi) - pembuatan kunci - kunci digeser tiap putaran
def left_shift(k, n):
    return k[n:] + k[:n]

def generate_keys(key_bin):
    #hasilin 16 kunci putaran
    #permutasi - 64 bit > 56 bit
    key_56bit = permute(key_bin, PC1)
    
    C, D = key_56bit[:28], key_56bit[28:]
    
    #geseran tiap putaran (standar DES)
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    round_keys = []
    for i in range(16):
        C = left_shift(C, shifts[i])
        D = left_shift(D, shifts[i])
        
        #gabungan C n D, lalu permutasi (56 bit > 48 bit) buat kunci putaran
        key_48bit = permute(C + D, PC2)
        round_keys.append(key_48bit)
    return round_keys

def f_function(right_half, round_key):
    #mesin pengacak buat tiap putaran
    #ekspansi (32 bit > 48 bit) caranya di duplikat bitnya
    expanded_right = permute(right_half, E)

    xored = xor(expanded_right, round_key)
    
    #substitusi (48 bit diproses dlm 8 potongan > 32 bit)
    sbox_output = ""
    for i in range(8):
        chunk = xored[i*6:(i+1)*6] #ambil 1 data 6 bit
        row = int(chunk[0] + chunk[5], 2) #cara temuin baris > digit 1 n digit akhir lalu gabungin
        col = int(chunk[1:5], 2) #cara temuin kolom > 4 digit tengahnya 
        sbox_output += format(S_BOX[i][row][col], '04b')
    return permute(sbox_output, P) #diacak lagi

def des_process(block_bin, round_keys, mode='encrypt'):
    #acak urutan bit
    permuted_block = permute(block_bin, IP)
    
    L, R = permuted_block[:32], permuted_block[32:]

    if mode == 'decrypt':
        round_keys.reverse()
    
    for i in range(16): #16 putaran Feistel
        L_old = L
        R_old = R

        f_result = f_function(R_old, round_keys[i]) #fungsi feistel
        
        L = R_old
        R = xor(L_old, f_result)
        final_block = R + L
    return permute(final_block, FP) #kebalikan dr IP 

if __name__ == "__main__":
    the_key = "rahasiaa" #8 karakter 64 bit
    plain_text = "IniTest" #kelipatan 8

    print("--- Implementasi & Testing DES Manual")
    print(f"Pesan Asli: {plain_text}")
    print(f"Kunci: {the_key}")

    key_bin = text_to_bin(the_key)
    plain_text_bin = text_to_bin(plain_text)

    round_keys_encrypt = generate_keys(key_bin)

    print("\n--- Mulai Enkripsi")
    ciphertext_bin = des_process(plain_text_bin, round_keys_encrypt, mode='encrypt')
    ciphertext_hex = bin_to_hex(ciphertext_bin)
    print(f"Hasil Enkripsi (Hex): {ciphertext_hex}")
    
    print("\n--- Mulai Dekripsi")
    round_keys_decrypt = generate_keys(key_bin) 
    decrypted_bin = des_process(ciphertext_bin, round_keys_decrypt, mode='decrypt')
    decrypted_text = bin_to_text(decrypted_bin)
    print(f"Hasil Dekripsi: {decrypted_text}")

    print("\n--- Verifikasi")
    if plain_text == decrypted_text:
        print("SUKSES - Pesan asli sama dengan pesan yang didekripsi")
    else:
        print("GAGAL - Pesan asli beda dengan pesan hasil dekripsi")
