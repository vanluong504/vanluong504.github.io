---
title: Grey Cat The Flags 2024 - Writeup
date: 2024-05-01 20-00-00
categories: [CTF]
tags: [CTF,Grey Cat 2024]
image: /assets/image/CTF/GreyCat2024/logo.png
math: true
---

### Filter Ciphertext

``filter_ciphertext.py``
```python
from Crypto.Cipher import AES
import os

with open("flag.txt", "r") as f:
    flag = f.read()

BLOCK_SIZE = 16
iv = os.urandom(BLOCK_SIZE)

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))

key = os.urandom(16)

def encrypt(pt):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    tmp = iv
    ret = b""
    
    for block in blocks:
        res = cipher.encrypt(xor(block, tmp))
        ret += res
        tmp = xor(block, res)
        
    return ret

    
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    for block in blocks:
        if block in secret_enc:
            blocks.remove(block)
    
    tmp = iv
    ret = b""
    
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        ret += res
        tmp = xor(block, res)
    
    return ret
    
secret = os.urandom(80)
secret_enc = encrypt(secret)

print(f"Encrypted secret: {secret_enc.hex()}")

print("Enter messages to decrypt (in hex): ")

while True:
    res = input("> ")

    try:
        enc = bytes.fromhex(res)

        if (enc == secret_enc):
            print("Nice try.")
            continue
        
        dec = decrypt(enc)
        if (dec == secret):
            print(f"Wow! Here's the flag: {flag}")
            break

        else:
            print(dec.hex())
        
    except Exception as e:
        print(e)
        continue
```

Hàm ``encrypt()`` hoạt động bằng cách chia ``pt`` thành các khối $B_0 B_1...B_n$ mỗi khối 16 bytes

$$
\begin{matrix}
C_0 = f(B_0 \oplus \text{iv}) \\
C_1 = f(B_1 \oplus B_0 \oplus C_0) \\
C_2 = f(B_2 \oplus B_1 \oplus C_1) \\
\vdots
\end{matrix}
$$

|![image](/assets/image/CTF/GreyCat2024/hinh1_filter_ciph.png)|
|:--|
|_Hình 1: Encrypt_|

Hàm ``decrypt()`` sẽ khôi phục plaintext từ ciphertext $ct = C_0 C_1 ... C_n$

$$
\begin{matrix}
B_0 = f^{-1}(C_0) \oplus \text{iv} \\
B_1 = f^{-1}(C_1) \oplus B_0 \oplus C_0 \\
B_2 = f^{-1}(C_2) \oplus B_1 \oplus C_1 \\
\vdots
\end{matrix}
$$

|![image](/assets/image/CTF/GreyCat2024/hinh2_filter_ciph.png)|
|:--|
|_Hình 2: Decrypt_|

PS: Trông khá lòng vòng và khó hiểu, mình đã phát hiện ra bug bài này. Khi ta nhập hai lần ``Encrypted secret`` thì server sẽ trả về flag.

![image](/assets/image/CTF/GreyCat2024/flag_filter_ciph.png)

### Filter Plaintext

``Filter_plaintext.py``
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import os

with open("flag.txt", "r") as f:
    flag = f.read()

BLOCK_SIZE = 16
iv = os.urandom(BLOCK_SIZE)

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))

key = os.urandom(16)

def encrypt(pt):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    tmp = iv
    ret = b""
    
    for block in blocks:
        res = cipher.encrypt(xor(block, tmp))
        ret += res
        tmp = xor(block, res)
        
    return ret

    
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    
    tmp = iv
    ret = b""
    
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        if (res not in secret):
            ret += res
        tmp = xor(block, res)
        
    return ret
    
secret = os.urandom(80)
secret_enc = encrypt(secret)

print(f"Encrypted secret: {secret_enc.hex()}")

secret_key = md5(secret).digest()
secret_iv = os.urandom(BLOCK_SIZE)
cipher = AES.new(key = secret_key, iv = secret_iv, mode = AES.MODE_CBC)
flag_enc = cipher.encrypt(pad(flag.encode(), BLOCK_SIZE))

print(f"iv: {secret_iv.hex()}")

print(f"ct: {flag_enc.hex()}")

print("Enter messages to decrypt (in hex): ")

while True:
    res = input("> ")

    try:
        enc = bytes.fromhex(res)
        dec = decrypt(enc)
        print(dec.hex())
        
    except Exception as e:
        print(e)
        continue
```

Chal này được mã hóa và giải mã theo

|![image](/assets/image/CTF/GreyCat2024/Pcbc_encryption.png)|
|:--|
|_Hình 1: Encrypt_|

|![image](/assets/image/CTF/GreyCat2024/Pcbc_decryption.png)|
|:--|
|_Hình 1: Decrypt_|

Sau khi đọc code thì ta nhận ra mình cần phải tìm được ``secret`` để biết được ``secret_key``
Tuy nhiên khi chúng ta decrypt ``enc_secret`` nếu như nó tồn tại trong ``secret`` thì sẽ bị xóa đi

Giờ chúng ta sẽ đi tìm ``iv`` để encrypt ``secret`` trước

```python
tmp = iv
ret = b""
    
for block in blocks:
    res = xor(cipher.decrypt(block), tmp)
    if (res not in secret):
        ret += res
    tmp = xor(block, res)
```

Khi chia ``enc_secret`` ra từng block, nếu chúng ta decrypt $encS0 + encS0$

Trong $res_0 = S_0$ sẽ bị xóa

Lúc này $tmp = D(encS_0) \oplus iv \oplus encS_0$ và sau đó nhận được  $res_1 = iv \oplus encS_0$

Từ đó ta có thể tìm lại ``iv``

Tiếp theo ta cần tìm $S_0$, nếu chúng ta decrypt $encS_1 + encS_0$ thì 

$res_0 = D(encS_1) \oplus iv$

$res_1 = D(encS_0) \oplus D(encS_1) \oplus iv \oplus encS_1 = S_0 \oplus D(encS_1) \oplus encS_1$

Bây giờ ta chỉ cần lần lượt gửi $encS_i$ đến thì $res_0 = D(encS_i) \oplus iv$

Tìm được $S_i = D(encS_i) \oplus encS_i \oplus S_{i-1} = res_O \oplus iv \oplus encS_i \oplus S_{i-1}$

Python Implementation: 
```python
from pwn import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5

f = remote("challs.nusgreyhats.org", 32223, level = 'debug')
# f = process(["python3", "filter_plaintext.py"])

enc_secret = bytes.fromhex((f.recvuntil("\n").decode()).replace("Encrypted secret: ",""))

iv = bytes.fromhex((f.recvuntil("\n").decode()).replace("iv: ",""))
ct = bytes.fromhex((f.recvuntil("\n").decode()).replace("ct: ",""))
f.recvline()
f.sendline(enc_secret[:16].hex() * 2)
dec = bytes.fromhex((f.recvuntil("\n").decode()).replace("> ", ""))
print(dec)

iv_secret = xor(dec, enc_secret[:16])
print("IV Secret:", iv_secret.hex())

f.sendline(enc_secret[16:32].hex() + enc_secret[:16].hex())
dec = bytes.fromhex((f.recvuntil("\n").decode()).replace("> ", ""))
print(dec)

dec_ct1 = xor(dec[:16], iv_secret)
secret = xor(dec[16:32], dec_ct1)
secret = xor(secret, enc_secret[16:32])

print("Secret:", secret.hex())

for i in range(16, len(enc_secret), 16):
    f.sendline(enc_secret[i:i + 16].hex())
    dec = bytes.fromhex((f.recvuntil("\n").decode()).replace("> ", ""))
    tmp = xor(dec, iv_secret)
    tmp = xor(tmp, enc_secret[i - 16:i])
    tmp = xor(tmp, secret[i - 16:i])
    secret += tmp
    print("Secret:", secret.hex())

cipher = AES.new(key=md5(secret).digest(), iv=iv, mode=AES.MODE_CBC)
print(cipher.decrypt(ct))
f.close()
```

### AES

``AES_server.py``
```python
from secrets import token_bytes

# Adapted from https://github.com/boppreh/aes/blob/master/aes.py

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

def mix_single_column(a):
    a[0], a[1], a[2], a[3] = a[1], a[2], a[3], a[0]

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

class AES:
    def __init__(self, master_key) -> None:
        assert len(master_key) == 16
        self.n_rounds = 10
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4
        i = 1

        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])
            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)
    
    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self.encrypt_block(plaintext[i : i + 16])
        return ciphertext

FLAG = 'REDACTED'
password = token_bytes(16)
key = token_bytes(16)

AES = AES(key)
m = bytes.fromhex(input("m: "))
if (len(m) > 4096): exit(0)
print("c:", AES.encrypt(m).hex())

print("c_p:", AES.encrypt(password).hex())
check = input("password: ")
if check == password.hex():
    print('flag:', FLAG)
```

Để lấy được flag thì chúng ta cần phải nhập đúng passwd sau khi giải mã ``c_p``

```python
if check == password.hex():
    print('flag:', "greyctf:::::::")
```

Như ta thấy ở mix_columns() có sự khác biệt

``original``
```python
def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])
```

``new chall greycat``
```python
def mix_single_column(a):
    a[0], a[1], a[2], a[3] = a[1], a[2], a[3], a[0]

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])
```

Để hiểu rõ hơn chúng ta cần print() ở hàm ``encrypt_block()``
```python
def encrypt_block(self, plaintext):
    assert len(plaintext) == 16
    plain_state = bytes2matrix(plaintext)
    add_round_key(plain_state, self._key_matrices[0])
    for i in range(1, self.n_rounds):
        sub_bytes(plain_state)
        shift_rows(plain_state)
        mix_columns(plain_state)
        add_round_key(plain_state, self._key_matrices[i])
        print(plain_state)
    sub_bytes(plain_state)
    shift_rows(plain_state)
    add_round_key(plain_state, self._key_matrices[-1])
    print(plain_state)
    return matrix2bytes(plain_state)
```

Chúng ta sẽ thử đoạn code này để xem sự biến thứ tự của plaintext đối với ciphertext

```python
from aes import*
from pwn import *

AES = AES(b'0' * 16)
ct = AES.encrypt(b'\x00'*16)[:16]
print()
x = AES.encrypt(b'\xaa' + b'\x00'*15)
```
```text
[[49, 48, 48, 48], [1, 0, 0, 0], [49, 48, 48, 48], [1, 0, 0, 0]]
[[166, 194, 165, 152], [196, 161, 198, 39], [150, 242, 149, 168], [244, 145, 246, 23]]
[[122, 101, 73, 247], [1, 207, 61, 148], [252, 125, 65, 119], [168, 61, 189, 51]]
[[109, 30, 30, 84], [144, 106, 206, 122], [53, 80, 9, 81], [210, 197, 161, 175]]
[[109, 188, 152, 105], [83, 159, 103, 51], [180, 180, 182, 36], [255, 175, 233, 106]]
[[162, 244, 125, 52], [244, 9, 193, 182], [18, 151, 151, 100], [131, 112, 90, 32]]
[[222, 98, 205, 188], [46, 67, 90, 98], [156, 211, 88, 253], [148, 161, 57, 238]]
[[112, 90, 37, 106], [170, 223, 42, 155], [51, 92, 243, 64], [128, 134, 119, 190]]
[[232, 27, 125, 195], [240, 46, 158, 148], [255, 5, 209, 101], [47, 231, 239, 247]]
[[172, 169, 109, 123], [1, 40, 16, 5], [32, 237, 245, 175], [178, 212, 231, 250]]
[[130, 131, 131, 131], [178, 179, 179, 179], [130, 131, 131, 131], [178, 179, 179, 179]]
[[168, 42, 171, 76], [44, 175, 46, 108], [152, 26, 155, 124], [28, 159, 30, 92]]
[[49, 91, 243, 17], [42, 255, 82, 249], [166, 25, 221, 161], [104, 184, 111, 16]]
[[241, 92, 23, 73], [187, 184, 36, 227], [126, 102, 178, 197], [166, 226, 102, 40]]
[[3, 138, 213, 244], [51, 158, 124, 185], [138, 54, 125, 65], [199, 18, 158, 251]]
[[114, 69, 112, 115], [124, 28, 135, 152], [162, 210, 2, 151], [152, 229, 239, 240]]
[[67, 157, 246, 198], [19, 34, 205, 205], [20, 125, 80, 14], [69, 206, 242, 68]]
[[249, 99, 22, 109], [51, 68, 251, 215], [138, 163, 228, 100], [116, 133, 136, 242]]
[[109, 127, 90, 11], [176, 31, 160, 251], [44, 125, 203, 216], [106, 13, 165, 168]]
[[11, 88, 76, 209], [106, 188, 201, 0], [71, 174, 180, 130], [165, 169, 12, 214]]

[[49, 48, 48, 140], [1, 0, 0, 0], [49, 48, 48, 48], [1, 0, 0, 0]]
[[166, 194, 165, 152], [196, 161, 166, 39], [150, 242, 149, 168], [244, 145, 246, 23]]
[[122, 101, 73, 247], [1, 207, 61, 148], [252, 125, 65, 119], [168, 173, 189, 51]]
[[109, 30, 30, 84], [144, 106, 206, 122], [135, 80, 9, 81], [210, 197, 161, 175]]
[[109, 188, 152, 105], [83, 159, 103, 51], [180, 180, 182, 165], [255, 175, 233, 106]]
[[162, 244, 125, 52], [244, 9, 193, 182], [18, 151, 151, 100], [131, 112, 106, 32]]
[[222, 98, 205, 188], [46, 255, 90, 98], [156, 211, 88, 253], [148, 161, 57, 238]]
[[124, 90, 37, 106], [170, 223, 42, 155], [51, 92, 243, 64], [128, 134, 119, 190]]
[[232, 27, 125, 130], [240, 46, 158, 148], [255, 5, 209, 101], [47, 231, 239, 247]]
[[172, 169, 109, 123], [1, 40, 16, 56], [32, 237, 245, 175], [178, 212, 231, 250]]
[[130, 131, 131, 131], [178, 179, 179, 179], [130, 131, 131, 131], [178, 179, 179, 179]]
[[168, 42, 171, 76], [44, 175, 46, 108], [152, 26, 155, 124], [28, 159, 30, 92]]
[[49, 91, 243, 17], [42, 255, 82, 249], [166, 25, 221, 161], [104, 184, 111, 16]]
[[241, 92, 23, 73], [187, 184, 36, 227], [126, 102, 178, 197], [166, 226, 102, 40]]
[[3, 138, 213, 244], [51, 158, 124, 185], [138, 54, 125, 65], [199, 18, 158, 251]]
[[114, 69, 112, 115], [124, 28, 135, 152], [162, 210, 2, 151], [152, 229, 239, 240]]
[[67, 157, 246, 198], [19, 34, 205, 205], [20, 125, 80, 14], [69, 206, 242, 68]]
[[249, 99, 22, 109], [51, 68, 251, 215], [138, 163, 228, 100], [116, 133, 136, 242]]
[[109, 127, 90, 11], [176, 31, 160, 251], [44, 125, 203, 216], [106, 13, 165, 168]]
[[11, 88, 76, 209], [106, 188, 201, 0], [71, 174, 180, 130], [165, 169, 12, 214]]
```

Như ta thấy sự khác biệt ở list đầu tiên giữa ``[49, 48, 48, 48]`` và [[49, 48, 48, 190]]

Tiếp theo đó mình sẽ gửi lần lượt theo qui luật dịch trái ``b'\xaa'`` cho đến hết để lấy được sự thay đổi của nó

```python
from aes import*
from pwn import *
from Crypto.Util.number import*

AES = AES(b'0' * 16)
ct = AES.encrypt(b'\x00'*16)[:16]

partners = []
for i in range(16):
    payload = b"\x00"*i + b'\xaa' + b'\x00'*(15-i)
    new_ct = AES.encrypt(payload)
    for j in range(16):
        if new_ct[j] != ct[j]:partners.append(j)
print(partners) 
# [7, 12, 5, 14, 11, 0, 9, 2, 15, 4, 13, 6, 3, 8, 1, 10]
```

Giờ ta sẽ tấn công từng ký tự của passwd, nếu đúng byte đầu tiên, thì byte thứ 8 của ``xor(enc_p,ct)`` sẽ là byte 00, tiếp tục như thế với byte thứ 2 của passwd, thì byte thứ 13 của xor(enc_p,ct) sẽ là 00

Việc tìm lại passwd rất đơn giản.

Python Implementation:
```python
from pwn import *
from aes import *
from Crypto.Util.number import long_to_bytes, bytes_to_long 

f = remote('challs.nusgreyhats.org', 35100, level = 'debug')

plaintext = b''
for i in range(256):
    plaintext += bytes([i]*16)

id = [7, 12, 5, 14, 11, 0, 9, 2, 15, 4, 13, 6, 3, 8, 1, 10]

f.recvuntil(b'm: ')
f.sendline(plaintext.hex().encode())

f.recvuntil(b'c: ')
c = bytes.fromhex(f.recvline().strip().decode())
print(len(c))

f.recvuntil(b'c_p: ')
enc_p = bytes.fromhex(f.recvline().strip().decode())
enc_p = enc_p[:16]

pw = [b'\x00']*16
for i in range(256):
    block = c[i*16: (i+1)*16]
    l = xor(block, enc_p)
    for idx in range(len(l)):
        if l[idx] == 0:
            pw[id[idx]] = bytes([i])
            break

pw = b''.join(pw)
pw = list(pw)
for i in range(0, len(pw), 4):
    pw[i:i+4] = pw[i+2: i+4] + pw[i:i+2]

pw = bytes(pw)
f.sendline(pw.hex().encode())
f.interactive()
```
### PRG

``server.py``
```python
from secrets import token_bytes, randbits
from param import A 
import numpy as np

FLAG = 'REDACTED'

A = np.array(A)

def print_art():
    print(r"""
            />_________________________________
    [########[]_________________________________>
            \>
    """)
    
def bytes_to_bits(s):
    return list(map(int, ''.join(format(x, '08b') for x in s)))

def bits_to_bytes(b):
    return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))

def prg(length):
    x = token_bytes(8); r = token_bytes(8); k = token_bytes(8)
    x = np.array(bytes_to_bits(x)); r = np.array(bytes_to_bits(r)); k = np.array(bytes_to_bits(k))
    output = []
    for i in range(length * 8):
        output.append(sum(x) % 2)
        if (i % 3 == 0): x = (A @ x + r) % 2
        if (i % 3 == 1): x = (A @ x + k) % 2
        if (i % 3 == 2): x = (A @ x + r + k) % 2
    output = output
    return bits_to_bytes(output).hex()
    
def true_random(length):
    return token_bytes(length).hex()

def main():
    try:
        print_art()
        print("I try to create my own PRG")
        print("This should be secure...")
        print("If you can win my security game for 100 times, then I will give you the flag")
        for i in range(100):
            print(f"Game {i}")
            print("Output: ", end="")
            game = randbits(1)
            if (game): print(prg(16))
            else: print(true_random(16))
            guess = int(input("What's your guess? (0/1): "))
            if guess != game:
                print("You lose")
                return
        print(f"Congrats! Here is your flag: {FLAG}")
    except Exception as e:
        return

if __name__ == "__main__":
    main()

# A = [
#     [0,1,1,1,0,0,0,1,0,1,1,1,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,0,0,1,1,0,1,1,0,1,1,0,1,1,0,1,0,0,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,0,1,1,0],
#     [1,1,1,1,1,1,0,1,0,0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,0,0,0,1,1,0,1],
#     [0,1,0,1,1,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,0,0,0,1,1,0,0,1,1,1,1,1,0,1,0,0,1,1,0,0,1,1,0,1,0,1,1,1,0,1,1,0,0,0,0,0,1,1,0,0],
#     [1,0,1,1,0,1,1,1,0,1,0,0,0,0,0,1,0,0,0,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,0,0,1,0,1,0,1,1,1,1],
#     [0,0,0,1,1,0,1,1,1,1,1,1,1,1,0,0,1,0,1,0,0,0,1,1,0,0,0,1,1,1,1,0,1,1,1,0,1,1,0,1,1,1,0,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,0,0,1],
#     [0,1,0,1,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,1,1,0,0,1,1,1,0,1,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,0,0],
#     [0,0,1,0,0,0,1,0,0,0,0,1,0,0,1,0,1,0,0,0,1,0,1,0,1,0,1,0,0,0,1,0,0,1,1,1,1,0,0,1,0,0,0,1,0,1,0,1,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,0],
#     [1,1,1,0,0,0,1,1,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,1,1,1,1,0,1,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,1,1],
#     [1,1,1,1,1,1,0,1,1,1,0,0,0,0,1,1,0,0,1,1,1,0,0,0,1,1,0,0,1,1,1,1,1,0,1,0,0,0,0,0,1,1,1,1,0,0,1,1,1,1,1,0,1,1,1,1,1,1,0,1,0,1,1,1],
#     [1,1,0,0,0,0,0,1,1,1,1,0,0,0,0,0,1,0,1,0,1,1,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,0,1,0,1,1,0,0,1,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,1,0],
#     [1,1,0,1,0,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,1,1,0,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,1],
#     [0,0,1,0,0,0,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,0,1,1,0,1,1,0,0,1,1,0,1,1,0,0,1,0,0,1],
#     [0,1,1,1,0,0,0,0,0,1,0,0,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,1,0,0,1,1,1,1,1,1,1,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,1],
#     [1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,1,1,0,1,0,1,1,1],
#     [1,1,1,0,1,1,1,0,1,0,1,1,0,0,0,0,1,1,0,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,0,0,1,0,0,1,0,0,1,0,1,1,1],
#     [0,1,0,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,1,0,0,0,0,1,0,1,0],
#     [1,0,0,1,0,1,1,1,1,1,1,1,0,0,0,0,1,0,1,0,1,1,1,1,1,1,1,1,0,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,1,1,0,1,1,1,1,0,1,0,1,0,0,1,1,0,1,1,0],
#     [0,0,1,1,0,1,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,0,0,1,1,1,0,1,0,1,1,1,0,0],
#     [1,0,0,1,1,0,1,1,0,0,0,1,0,0,1,1,0,1,1,0,1,1,0,1,1,0,0,0,0,1,1,1,0,1,0,1,1,0,0,0,1,1,1,0,1,1,1,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,1,0],
#     [0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,0,0,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,0,1,1,1,0,1,0,1,0],
#     [0,0,1,0,1,0,0,1,0,1,0,1,0,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,1,1,1,0,1,1,1,0,1,0,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,1,0,0],
#     [1,0,0,1,1,0,1,1,0,0,0,1,1,1,0,1,0,1,1,1,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,1,0,1,0,0,0,0,0,1,1,0,1,1,1,1,0,1,1,0,0,1,1,0,1,0],
#     [0,0,0,1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,0,0,1,1,0,1,1,1,0,1,1,0,1,1,0,0,0,0,0,0,0,1,0,0,1,0,1,0,0,0,0,1,0,0,1,1,0,0,0,1,0,0,0,0],
#     [0,1,0,1,0,1,1,1,0,1,0,1,1,0,0,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,1,1,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0,1,0,1,0],
#     [1,0,0,1,1,1,0,1,0,0,1,1,1,0,0,1,1,1,1,1,1,1,0,1,1,0,0,0,0,0,0,1,1,0,1,1,0,1,1,1,0,0,0,0,1,0,1,1,1,0,1,1,1,1,0,1,0,1,1,0,1,0,0,1],
#     [0,1,0,0,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,1,0,1,0,1,0,1,1,0,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,0,0,1,0,1,0,0,0,0,1,0,0,1,0,1,0,1,0,0],
#     [0,0,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,1,1,1,0,1,0,0,1,1,1,1,1,1,0,0,0,1,1,0,1,0,1,0,1,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,1,0,1,0,1],
#     [1,1,0,0,1,0,0,1,1,0,0,0,0,0,1,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,0,1,0,0,0,0,1,1,0,1,1,1,0,1,0,1,0,1,0,0,0,0,0,0,0],
#     [0,0,0,1,0,0,1,0,1,0,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,1,0],
#     [0,1,1,0,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,1,0,1,0,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,0,0,0,0],
#     [1,0,1,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,1,1,0,1,0,0,0,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,1,0,0,1,0,0,1,1,1,0,0,1,0,0,0,0,1,1,0,1,1,1,0,1],
#     [0,0,1,1,0,0,1,0,1,1,0,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,1,0,0,0,0,1,0,1,1,0,0,0,0,0,0,0,1,0,1,0,1,0,1,1,1,1,1,0,1,0,1,1,0,1,0,0,1],
#     [1,1,1,1,0,0,0,0,0,1,0,0,1,1,0,1,1,0,1,0,0,0,0,1,1,1,1,0,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,0,1,1,1,1,0,0],
#     [1,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,0,1,1,1,0,1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,1,0,1,0,1,1],
#     [1,1,0,1,0,1,0,1,0,0,1,1,1,1,1,0,0,0,1,0,1,1,0,1,1,0,0,0,0,1,0,1,1,1,0,0,1,1,1,0,0,0,1,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,0,0,0,1],
#     [0,1,1,0,0,0,1,1,1,0,1,1,1,0,1,0,0,0,0,1,0,0,1,0,0,1,0,1,1,1,0,0,1,1,0,0,1,0,0,1,0,0,0,1,0,1,1,0,0,0,1,0,0,0,0,0,1,0,0,0,1,0,1,1],
#     [0,0,0,1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,0,1,0,0,0,1,0,1,1,0,0,1,1,1,1,1,0,0,1,1,1,0,1,0,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1],
#     [0,1,1,0,0,1,0,1,1,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,1,1,1,1,0,1,0,0,1,1,1,1,0,0,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,1,0,1],
#     [1,1,0,0,0,1,0,1,0,0,0,1,1,0,1,0,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,1,1,0,1,1,0,1,0,0,0,1,1,1,1,1,0,0],
#     [1,0,1,1,1,1,1,1,0,0,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,0,0,0,0,1,1,0,0,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,0,0,1,0,1,1,0,1,1,1,1,0,0,0],
#     [1,0,1,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,0,0,1,1,1,1,1,0,0,0,1,1,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,1,1,1,0,1,1,1,0],
#     [1,0,0,1,1,0,1,1,1,1,0,1,1,0,1,1,0,1,0,1,1,1,1,0,1,1,1,0,0,1,0,0,0,1,0,0,1,0,1,0,0,1,1,1,0,1,0,0,0,0,1,1,1,0,1,1,0,0,0,0,0,1,0,1],
#     [1,1,0,1,0,0,1,0,0,0,1,0,1,1,1,1,0,0,0,1,1,0,1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,0,1,1,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,1,1,1,0,0,0,0],
#     [1,1,1,1,1,0,1,1,1,0,0,0,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,0,0,0,0,1,1,1,0,0,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,1,0,0,0,1,1],
#     [0,0,1,0,1,1,0,0,1,0,1,1,0,0,1,0,0,0,1,0,1,0,0,0,0,1,1,0,1,1,0,1,0,1,0,0,1,0,0,1,1,1,0,0,1,1,0,1,1,1,1,0,0,1,1,0,0,1,0,1,0,0,0,1],
#     [0,0,0,0,1,0,1,0,0,0,0,1,0,1,1,1,0,0,0,0,0,1,1,1,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,1,0,1,0,1,1,1,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,1],
#     [1,0,1,0,0,0,1,0,0,0,1,0,1,1,0,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,0,0,0,0],
#     [0,1,0,1,0,0,0,0,0,1,1,0,0,1,1,1,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,0,1,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,1,0,1,1,1,1,0,1,0],
#     [1,0,0,1,1,1,1,1,1,1,1,1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,0,0,0,1,0,1,1,1,1,0,1,1,1,0,0,0,1,0,1,1,1,1,1,0,0,1,1],
#     [0,0,1,0,1,1,0,1,0,1,1,1,1,0,0,0,0,1,0,0,0,1,0,0,1,1,1,1,0,0,1,1,0,0,1,1,0,0,0,0,0,1,1,0,1,0,0,1,1,0,0,0,0,0,1,1,0,1,1,1,0,1,0,0],
#     [1,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,0,0,0,1,1,1,1,0,1,1,1,0,1,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0],
#     [0,1,0,0,0,1,1,0,1,0,0,1,0,1,0,1,1,1,1,1,0,1,0,1,0,1,0,0,1,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,1,1,1,0,1,1,0,0,1,0,0,1,1,0,1,0,1,0,1,1],
#     [0,1,0,1,1,1,1,0,0,1,0,0,1,0,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,0,0,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,0,0,0,1,1,0,0,0,0,0,0,0,1,1,1,1],
#     [1,1,1,1,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,0,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,0,0,1,1,0,1,0,1,0,0,1,1,0,0,0,0,0],
#     [0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,1,1,0,0,0,1,1,0,0,1,1,1,1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,1,0,0,1,1,1,1,0,1,1,0,1,1,0,1,0,1,1,1,0],
#     [1,1,1,0,1,1,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,1,1,0,1,0,1,0,0,0,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,0,0,0,1,0,1,1,0,1,1],
#     [0,1,0,0,1,1,1,0,1,0,1,1,0,1,0,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,1,0,1,0,0,1,1,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1],
#     [0,1,1,1,0,0,0,1,0,1,1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,0,0,0,1,1,1,1,1,0,0,0,0,1,1,0,1,0,1,1,1,1,0,1,0,1,1,0,1,0,0,1,0,0,1,0,0,0,1,0],
#     [0,0,0,0,0,0,0,0,1,0,0,1,1,1,0,1,1,1,1,1,1,1,0,0,1,0,0,1,1,0,1,0,0,0,0,0,0,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,1,0,1,1,1,1,0,1,1,0,1,0],
#     [1,1,0,1,0,1,0,1,0,0,1,0,0,1,0,1,1,1,1,1,0,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,1,1,1,1,1,1,0,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,0,0,0,0,0,1],
#     [1,0,0,0,1,0,0,1,1,1,0,1,1,0,0,0,1,0,0,1,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0,0,1,0,0,1,0,1,1,1,1,1,0,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,0,1],
#     [1,0,0,1,0,0,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,0,1,1,0,1,0,1,0,1,0,1,1,1,1,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,0,0],
#     [1,1,1,1,1,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,0,0,0,0,1,1,1,0,1,1,0,0,1,0,1,1,1,1,1,0,0,1,0,1,0,0,1,0,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,1],
#     [0,1,1,0,1,1,0,1,0,1,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,0,1,0,1,0,1,1,1,0,0,1,1,1,1,1,0,1,1,0,1,0,1,1,0]
# ]
```

Đến với chal này chúng ta phải đúng 100 lần liên tiếp thì server mới trả về flag.

Trước hết, x, r, k được khởi tạo ngẫu nhiên 64 bit, chúng ta có pt dưới

$$
x(\mod 2)\mapsto\begin{cases}
Ax+r,&i\equiv0\pmod3 \\
Ax+k,&i\equiv1\pmod3 \\
Ax+r+k,&i\equiv2\pmod3, \\
\end{cases}
$$

Tạo vector $v = (v_1, \dots,v_{64}) \in F_2^{64}$ và tổng của v là $s(v)=\sum_i v_i$, các bit đầu ra $b_1, b_2, ..., b_{123}$ thỏa mãn phương trình

$$
\begin{matrix}
(x) = b_1 \\
(Ax+r) = b_2 \\
(A(Ax+r)+k) = b_3 \\
\vdots
\end{matrix}
$$

Ta có thể thấy vế trái có thể biểu diễn qua các biến $x_1,\ldots,x_{64},r_1,\ldots,r_{64},k_1,\ldots,k_{64},$

Cuối cùng nó là hệ 128 pt với 192 ẩn, rất dễ dàng thực thi với sage.

Python Implementation: 

```python
from pwn import *
from sage.all import *
from param import A
from tqdm import *

A = A
F = GF(2)

def X(i): return vector(F, [0 for _ in range(i)] + [1] + [0 for _ in range(3*64-i-1)])
def R(i): return vector(F, [0 for _ in range(64+i)] + [1] + [0 for _ in range(2*64-i-1)])
def K(i): return vector(F, [0 for _ in range(2*64+i)] + [1] + [0 for _ in range(64-i-1)])
Z = vector(F, [0 for _ in range(3*64)])

M = []
vs = []
for i in tqdm(range(64)):
    v = vector(F, X(i))
    vs.append(v)
M.append(sum(vs))

for n in tqdm(range(16*8-1)):
    if n%3 == 0: RK = R
    elif n%3 == 1: RK = K
    else: RK = lambda i: R(i)+K(i)

    new_vs = []
    for i in tqdm(range(64)):
        new_v = RK(i)
        for j in range(64):
            new_v += A[i][j] * vs[j]
        new_vs.append(new_v)
    M.append(sum(new_vs))
    vs = new_vs
M = Matrix(F, M)

def bytes_to_bits(s):
    return list(map(int, ''.join(format(x, '08b') for x in s)))

def bits_to_bytes(b):
    return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))

r = remote('challs.nusgreyhats.org', 35101, level = 'debug')
r.recvuntil(b'Output: ')
for i in tqdm(range(100)):
    L = r.recvline()
    print(L)
    v = vector(F, bytes_to_bits(bytes.fromhex(L[:-1].decode())))
    try:
        M.solve_right(v)
        result = b'1\n'
    except:
        result = b'0\n'
    r.send(result)
    print(result)
    if i < 99:
        r.recvuntil(b'Output: ')
    else:
        r.recvline()
```