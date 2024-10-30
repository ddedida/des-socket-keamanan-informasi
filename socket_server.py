import socket
from table import keyp, shift_table, key_comp
from util import hex_to_bin, bin_to_hex, left_shift, permutation, encrypt_ecb

def server_program():
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen()
    print(f"server berjalan di {host}:{port}")

    conn, address = server_socket.accept()
    print(f"menerima koneksi dari {address}\n")

    while True:
        pt = input("-> masukkan input plain text: ")
        key = "AABBCCDDEEFF1122"

        if (pt != 'bye'):
            print(f"plain text: {pt}")
            print(f"key: {key}")

            # KEY PROCESS
            key = hex_to_bin(key)
            key = permutation(key, keyp, 56)
            left = key[0:28]
            right = key[28:56]
            rk = []
            rkb = []

            for i in range(0, 16):
                # Left Shift
                left = left_shift(left, shift_table[i])
                right = left_shift(right, shift_table[i])

                # Combine
                combine_str = left + right

                # Compress to 48-bit
                round_key = permutation(combine_str, key_comp, 48)

                rkb.append(round_key)
                rk.append(bin_to_hex(round_key))

            cipher_text_bin, last_char = encrypt_ecb(pt, rkb, rk)
            cipher_text = bin_to_hex(cipher_text_bin) + last_char
            
            conn.send(cipher_text.encode())
        else:
            break

    conn.close()

if __name__ == '__main__':
    server_program()