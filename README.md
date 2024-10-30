# Implementasi DES Client Server - Keamanan Informasi

```json
Nama: Dewangga Dika Darmawan
NRP: 5025211109
Kelas: Keamanan Informasi B
```

Pada tugas kali ini, disuruh untuk mengimplementasikan DES pada sisi server dan client. Di mana pada salah satu sisi misalnya server, dilakukan `encryption` pada <i>plain text</i> menjadi <i>chiper text</i>, lalu dilakukan `decryption` pada <i>chiper text</i> menjadi <i>plain text</i> pada sisi client. Di mana terdapat beberapa aturan:

- Implementasi transfer string terenkripsi antar 2 user menggunakan socket programming.
- String enkripsi wajib dikirimkan melalui socket (tidak boleh read/write file).
- Enkripsi dan Dekripsi harus bisa menerima input lebih dari 64 bit.

Kode ini adalah pengembangan dari kode DES [sebelumnya](https://github.com/ddedida/des-keamanan-informasi), di mana kode tersebut belum diimplementasikan socket programming. Pada implementasikan dibuatkan 4 file yaitu:

- `socket_client.py`: client menerima <i>chiper text</i> dari server lalu mendekripsinya menjadi <i>plain_text</i> dan menampilkannya di terminal.
- `socket_server.py`: server menerima input untuk <i>plain text</i> lalu mengenkripsinya menjadi <i>chiper text</i> lalu mengirimkannya ke client.
- `table.py`: berisi tabel-tabel yang digunakan untuk algoritma DES.
- `util.py`: berisi fungsi-fungsi untuk melakukan enkripsi dan dekripsi DES.

Flow dari kode ini cukup sederhana yakni:

1. Memasukkan input <i>plain text</i> pada server, lalu hasil enkripsinya dikirimkan ke client.
2. Client menerima <i>chiper text</i> hasil enkripsi server dan mendekripsinya menjadi <i>plain text</i> dan hasilnya ditampilkan di terminal.

Di mana tantangan sebenarnya adalah bagaimana melakukan enkripsi dan dekripsi untuk input yang lebih dari 64 bit. Solusi pada kode ini adalah menggunakan metode EBC (<i>Electronic Code Block</i>). Di mana plain text aakan dipecah menjadi blok-blok yang terpisah dan mengenkripsi setiap blok secara independen dengan kunci yang sama.

Pada kode ini blok kode akan berisi sebanyak 16 karakter (64 bit). Misalnya, plain text berisi 20 karakter (80 bit), akan dibagi 2 blok yaitu 16 dan 4 karakter. Namun, pada DES proses enkripsi dan dekripsi harus berisi 16 karakter (64 bit). Oleh karena itu, blok yang kekurangan karakter akan ditambahkan karakter `0` sebanyak yang dibutuhkan.

Namun hal tersebut akan menyebabkan plain text yang ditampilkan pada sisi client berbeda dengan yang diinputkan. Solusi dari masalah tersebut yaitu menambahkan carry dibelakang chiper_text yang dikirimkan. Begini prosesnya:

1.  Dimasukkan input sebanyak 20 karakter (80 bit). Sebelum dibagi menjadi blok-blok, apabila input bukan kelipatan 16 maka akan ditambahkan padding terlebih dahulu menggunakan fungsi `pad` di mana fungsi tersebut dipanggil pada fungsi `encrypt_ecb`

    ```py
    # util.py

    def encrypt_ecb(pt, rkb, rk):
    last_index = ""
    if (len(pt) % 16 != 0):
    	pt, last_index = pad(pt)
    cipher_text = ""
    num_blocks = len(pt) // 16
    for i in range(num_blocks):
    	block = pt[i * 16:(i + 1) * 16]
    	encrypted_block = encrypt(block, rkb, rk)
    	cipher_text += encrypted_block
    return cipher_text, last_index
    ```

    ```py
    # util.py

    def pad(pt):
    padding = ""
    padding_len = 16 - (len(pt) % 16)
    last_index = bin_to_hex(dec_to_bin(padding_len))
    padding += "0" * padding_len
    return (pt + padding), last_index
    ```

    Sebelum padding:

    - input plain text: `123456789ABCDEF11234` (20 karakter, kekurangan 12 karakter)

    Setelah padding:

    - input plain text: `123456789ABCDEF11234000000000000`
    - blok 1: `123456789ABCDEF1`
    - blok 2: `1234000000000000`

2.  Pada fungsi tersebut direturn juga `last_index` yang berisi jumlah padding yang dibutuhkan dalam bentuk hexadecimal. Pada contoh dibutuhkan 12 padding maka `last_index` berisi `C` yang apabila diubah menjadi decimal menjadi `12` sesuai pada fungsi `bin_to_hex` di bawah.

    ```py
    # util.py

    # Binary to Hexadecimal Conversion
    def bin_to_hex(s):
        mp = {
            "0000": '0',
            "0001": '1',
            "0010": '2',
            "0011": '3',
            "0100": '4',
            "0101": '5',
            "0110": '6',
            "0111": '7',
            "1000": '8',
            "1001": '9',
            "1010": 'A',
            "1011": 'B',
            "1100": 'C',
            "1101": 'D',
            "1110": 'E',
            "1111": 'F'
        }
        hex = ""
        for i in range(0, len(s), 4):
            ch = ""
            ch = ch + s[i]
            ch = ch + s[i + 1]
            ch = ch + s[i + 2]
            ch = ch + s[i + 3]
            hex = hex + mp[ch]
        return hex
    ```

3.  Variabel `last_index` lalu akan digabungkan dengan plain text yang sudah menjadi chiper text lalu dikirimkan ke sisi client.

    ```py
    # socket_server.py
    ...
    cipher_text_bin, last_char = encrypt_ecb(pt, rkb, rk)
    cipher_text = bin_to_hex(cipher_text_bin) + last_char

    conn.send(cipher_text.encode())
    ...
    ```

    Variabel `last_index` digunakan untuk menentukan apakah input yang diberikan memerlukan padding atau tidak. Sebagai contoh, jika input awalnya 20 karakter, maka akan ditambahkan padding sebanyak 12 karakter sehingga panjangnya menjadi 32 karakter. Jika ada pengguna yang memberikan input dengan panjang tepat 32 karakter, maka padding tidak diperlukan. Oleh karena itu, `last_index` hanya akan memiliki nilai ketika panjang input bukan kelipatan 16.

4.  Pada sisi client data yang masuk akan dicek apakah data tersebut adalah cipher text yang ditambahkan padding atau tidak

    ```py
    # socket_client.py
    ...
    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break
        key = "AABBCCDDEEFF1122"

        if(len(data) % 16 != 0):
            chiper_text = data[:-1]
        else:
            chiper_text = data
    ...
    ```

    Apabila datanya bukan kelipatan 16 maka data tersebut adalah cipher text yang ditambahkan padding, maka dari itu kita harus menghapus index terakhir dari data tersebut.

5.  Lalu dilakukan dekripsi untuk cipher text tersebut dengan mereverse round key yang ada.

    ```py
    # socket_client.py
    ...
    rk_rev = rk[::-1]
    rkb_rev = rkb[::-1]

    plain_text = bin_to_hex(decrypt_ecb(chiper_text, rkb_rev, rk_rev))
    ...
    ```

6.  Lalu, apabila data yang masuk tadi adalah cipher text yang ditambahkan padding, dilakukan penghapusan sebanyak padding yang ditambahkan melalui variabel `padding_len`. Di mana variabel mengambil index terakhir dari data lalu yang berbentuk hexadecimal lalu diubah menjadi decimal.
    ```py
    # socket_client.py
    ...
    if(len(data) % 16 != 0):
        padding_len = bin_to_dec(int(hex_to_bin(data[-1])))
        plain_text = plain_text[:-padding_len]
        print(f"plain text: {plain_text}")
    else:
        print(f"plain text: {plain_text}")
    ...
    ```

## Contoh Input dan Output

1. Input 16 karakter
   **server**
   ![input 16 - server](https://cdn.discordapp.com/attachments/702797283795927123/1301091721693626438/input_16_-_server.png?ex=67233797&is=6721e617&hm=bc3e4dac3274354fb6a2809330258245fa64a571695d2c4c195ebda3d1a640a7&)

   **client**
   ![input 16 - client](https://cdn.discordapp.com/attachments/702797283795927123/1301091722016849991/input_16_-_client.png?ex=67233797&is=6721e617&hm=f888487ac51d36b234d1bb3d20554501ef5a9c7a27d357677a357cf4103df046&)

2. Input 20 karakter
   **server**
   ![input 20 - server](https://cdn.discordapp.com/attachments/702797283795927123/1301091754891673600/input_20_-_server.png?ex=6723379f&is=6721e61f&hm=e3943e2d1c7e0c544724b1fa60f6b3be04e337c19fd6c57882943d1302790217&)

   **client**
   ![input 20 - client](https://cdn.discordapp.com/attachments/702797283795927123/1301091755281612840/input_20_-_client.png?ex=6723379f&is=6721e61f&hm=e4d67b33d0a0e5ae6d9a7752cc5c07499c723296cdf8ee78f9cdbb834c18245a&)

3. Input 32 karakter
   **server**
   ![input 32 - server](https://cdn.discordapp.com/attachments/702797283795927123/1301091772335652875/input_32_-_server.png?ex=672337a3&is=6721e623&hm=40fca859e5ab2d706499f26cbc0a30cbb74d7bcbe6137b4930dd688758e5f9d1&)

   **client**
   ![input 32 - client](https://cdn.discordapp.com/attachments/702797283795927123/1301091772574863410/input_32_-_client.png?ex=672337a3&is=6721e623&hm=18ebcd682b7c59ae84b2cc342472074646ec5b70fbdaf04cdff917b9cd46c89d&)

4. Input `bye` sebagai tanda koneksi ditutup
   **server**
   ![input 16 - server](https://cdn.discordapp.com/attachments/702797283795927123/1301091793433264159/input_bye_-_server.png?ex=672337a8&is=6721e628&hm=be8ae40f484dab575eb90574c9c69da604e3660978ea6116f5b4e85f960dbd7f&)

   **client**
   ![input 16 - server](https://cdn.discordapp.com/attachments/702797283795927123/1301091793735122944/input_bye_-_client.png?ex=672337a8&is=6721e628&hm=0aa794422c6de75474cfbe7771e4b96fa4e4dca3bb8ad9f35ff6aab72f5b4791&)

```js
console.log("Terima Kasih 👋");
```
