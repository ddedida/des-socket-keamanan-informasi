from table import initial_perm, exp_d, sbox, per, final_perm

# Hexadicimal to Binary Conversion
def hex_to_bin(s):
	mp = {
		'0': "0000",
		'1': "0001",
		'2': "0010",
		'3': "0011",
		'4': "0100",
		'5': "0101",
		'6': "0110",
		'7': "0111",
		'8': "1000",
		'9': "1001",
		'A': "1010",
		'B': "1011",
		'C': "1100",
		'D': "1101",
		'E': "1110",
		'F': "1111"
	}
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin

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

# Binary to Decimal Conversion
def bin_to_dec(binary):
	decimal, i = 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal

# Decimal to Binary Conversion
def dec_to_bin(num):
	res = bin(num).replace("0b", "")
	if(len(res) % 4 != 0):
		div = len(res) / 4
		div = int(div)
		counter = (4 * (div + 1)) - len(res)
		for i in range(0, counter):
			res = '0' + res
	return res

# Permutation Function
def permutation(k, arr, n):
	permutation = ""
	for i in range(0, n):
		permutation = permutation + k[arr[i] - 1]
	return permutation

# Left Shift Function
def left_shift(k, nth_shifts):
	s = ""
	for i in range(nth_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k

# XOR Function
def xor(a, b):
	ans = ""
	for i in range(len(a)):
		if a[i] == b[i]:
			ans = ans + "0"
		else:
			ans = ans + "1"
	return ans
	
# Encrypt Function
def encrypt(pt, rkb, rk):
	# Convert Plaintext to Binary
	pt = hex_to_bin(pt)

	# Initial Permutation
	pt = permutation(pt, initial_perm, 64)
	# print("After initial permutation", bin_to_hex(pt))

	# Splitting to LPT and RPT
	left = pt[0:32]
	right = pt[32:64]
	for i in range(0, 16):
		# Expansion D-box: Expanding the 32 bits data into 48 bits
		right_expanded = permutation(right, exp_d, 48)

		# XOR RTP with RoundKey
		xor_x = xor(right_expanded, rkb[i])

		# S-Box
		sbox_str = ""
		for j in range(0, 8):
			row = bin_to_dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
			col = bin_to_dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = sbox[j][row][col]
			sbox_str = sbox_str + dec_to_bin(val)

		# P-box
		sbox_str = permutation(sbox_str, per, 32)

		# XOR LTP and S-Box Output
		result = xor(left, sbox_str)
		left = result

		# Swap
		if(i != 15):
			left, right = right, left
		# print("Round ", i + 1, " ", bin_to_hex(left), " ", bin_to_hex(right), " ", rk[i])

	# Combine
	combine = left + right

	# Result with Final Permutation
	cipher_text = permutation(combine, final_perm, 64)
	return cipher_text

# Add Padding Function
def pad(pt):
	padding = ""
	padding_len = 16 - (len(pt) % 16)
	last_index = bin_to_hex(dec_to_bin(padding_len))
	padding += "0" * padding_len
	return (pt + padding), last_index

# ECB Function for Encrypt
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

# ECB Function for Decrypt
def decrypt_ecb(pt, rkb, rk):
	plain_text = ""
	num_blocks = len(pt) // 16
	for i in range(num_blocks):
		block = pt[i * 16:(i + 1) * 16]
		encrypted_block = encrypt(block, rkb, rk)
		plain_text += encrypted_block
	return plain_text