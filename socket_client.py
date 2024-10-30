import socket
from table import keyp, shift_table, key_comp
from util import hex_to_bin, bin_to_hex, left_shift, permutation, decrypt_ecb, bin_to_dec

def client_program():
    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break
        key = "AABBCCDDEEFF1122"

        if(len(data) % 16 != 0):
            chiper_text = data[:-1]
        else:
            chiper_text = data

        print(f"-> chiper text: {chiper_text}")
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

        rk_rev = rk[::-1]
        rkb_rev = rkb[::-1]

        plain_text = bin_to_hex(decrypt_ecb(chiper_text, rkb_rev, rk_rev))

        if(len(data) % 16 != 0):
            padding_len = bin_to_dec(int(hex_to_bin(data[-1])))
            plain_text = plain_text[:-padding_len]
            print(f"plain text: {plain_text}")
        else:
            print(f"plain text: {plain_text}")

    client_socket.close()

if __name__ == '__main__':
    client_program()