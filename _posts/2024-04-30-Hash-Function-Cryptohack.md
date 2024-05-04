---
title: Hash Function - Cryptohack
date: 2024-04-30 12:00:00
categories: [CTF, Cryptohack, Hash]
tags: [Cryptohack]
image: /assets/image/Hash/Hash_cryptohack.png
math: true
---

Hash Function I solved $\frac{7}{11}$ challenges and I continuously updated 

### Jack's Birthday Hash

Vì giá trị hash là chuỗi nhị phân 11 bits nên có tất cả $H = 2^{11} = 2048$ giá trị hash

Giả sử ``p(n)`` là xác suất sau khi hash 𝑛 lần sẽ gặp ít nhất 1 collision

Ta có xác suất không gặp collision nào sau 𝑛 lần hash là
 
$$\overline{p}(n) = \left( \frac{H-1}{H} \right)^{n}$$

$$p(k) = 1 - \left( \frac{n-1}{n} \right)^{k}$$

$$\Longrightarrow n(p)=\frac{\log(1-p)}{\log\left(1-\frac{1}{H}\right)}$$

$$\Longrightarrow n(0.5) \approx 1420$$

### Jack's Birthday Confusion

Gọi p(n) là xác suất sau khi hash n lần sẽ gặp ít nhất 1 collision giữa 2 secret

$$\overline{p}(n) = \frac{H}{H}\cdot\frac{H-1}{H}\cdots\frac{H-n+1}{H}$$

$$\Longrightarrow p(n) = 1 - \left(1-\frac{1}{H}\right)\cdot\left(1-\frac{2}{H}\right)\cdots\left(1-\frac{n-1}{H}\right)$$

Vì n < H nên $1 - \frac{n}{H} \approx e^{- \frac{n}{H}}$

$$\Longrightarrow p(n) \approx 1 - e^{-\frac{n^2}{2H}}$$

$$\Longrightarrow n(p) \approx\sqrt{2H\ln\frac{1}{1-p}}$$

$$\Longrightarrow n(0.75)  \approx 75.35$$

### Collider

``13389.py``
```python
import hashlib
from utils import listener


FLAG = "crypto{???????????????????????????????????}"


class Challenge():
    def __init__(self):
        self.before_input = "Give me a document to store\n"
        self.documents = {
            "508dcc4dbe9113b15a1f971639b335bd": b"Particle physics (also known as high energy physics) is a branch of physics that studies the nature of the particles that constitute matter and radiation. Although the word particle can refer to various types of very small objects (e.g. protons, gas particles, or even household dust), particle physics usually investigates the irreducibly smallest detectable particles and the fundamental interactions necessary to explain their behaviour.",
            "cb07ff7a5f043361b698c31046b8b0ab": b"The Large Hadron Collider (LHC) is the world's largest and highest-energy particle collider and the largest machine in the world. It was built by the European Organization for Nuclear Research (CERN) between 1998 and 2008 in collaboration with over 10,000 scientists and hundreds of universities and laboratories, as well as more than 100 countries.",
        }

    def challenge(self, msg):
        if "document" not in msg:
            self.exit = True
            return {"error": "You must send a document"}

        document = bytes.fromhex(msg["document"])
        document_hash = hashlib.md5(document).hexdigest()

        if document_hash in self.documents.keys():
            self.exit = True
            if self.documents[document_hash] == document:
                return {"error": "Document already exists in system"}
            else:
                return {"error": f"Document system crash, leaking flag: {FLAG}"}

        self.documents[document_hash] = document

        if len(self.documents) > 5:
            self.exit = True
            return {"error": "Too many documents in the system"}

        return {"success": f"Document {document_hash} added to system"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13389)
```

Với bài này ta chỉ cần gửi 1 cặp [collision](https://en.wikipedia.org/wiki/Collision_attack) thì server sẽ trả về flag.
```text
d131dd02c5e6eec4 693d9a0698aff95c 2fcab58712467eab 4004583eb8fb7f89
55ad340609f4b302 83e488832571415a 085125e8f7cdc99f d91dbdf280373c5b
d8823e3156348f5b ae6dacd436c919c6 dd53e2b487da03fd 02396306d248cda0
e99f33420f577ee8 ce54b67080a80d1e c69821bcb6a88393 96f9652b6ff72a70
d131dd02c5e6eec4 693d9a0698aff95c 2fcab50712467eab 4004583eb8fb7f89
55ad340609f4b302 83e4888325f1415a 085125e8f7cdc99f d91dbd7280373c5b
d8823e3156348f5b ae6dacd436c919c6 dd53e23487da03fd 02396306d248cda0
e99f33420f577ee8 ce54b67080280d1e c69821bcb6a88393 96f965ab6ff72a70
```

Python Implementation: 
```python
from pwn import *
from json import *
import hashlib

f = connect("socket.cryptohack.org", 13389, level = "debug")
f.recvline()
input1 = "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2"
input2 = "4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2"

f.sendline(dumps({"document": input1}).encode())
f.recvline()

f.sendline(dumps({"document": input2}).encode())
f.recvline()
```

### Hash Stuffing

``server.py``
```python
# 2^128 collision protection!
BLOCK_SIZE = 32

# Nothing up my sleeve numbers (ref: Dual_EC_DRBG P-256 coordinates)
W = [0x6b17d1f2, 0xe12c4247, 0xf8bce6e5, 0x63a440f2, 0x77037d81, 0x2deb33a0, 0xf4a13945, 0xd898c296]
X = [0x4fe342e2, 0xfe1a7f9b, 0x8ee7eb4a, 0x7c0f9e16, 0x2bce3357, 0x6b315ece, 0xcbb64068, 0x37bf51f5]
Y = [0xc97445f4, 0x5cdef9f0, 0xd3e05e1e, 0x585fc297, 0x235b82b5, 0xbe8ff3ef, 0xca67c598, 0x52018192]
Z = [0xb28ef557, 0xba31dfcb, 0xdd21ac46, 0xe2a91e3c, 0x304f44cb, 0x87058ada, 0x2cb81515, 0x1e610046]

# Lets work with bytes instead!
W_bytes = b''.join([x.to_bytes(4,'big') for x in W])
X_bytes = b''.join([x.to_bytes(4,'big') for x in X])
Y_bytes = b''.join([x.to_bytes(4,'big') for x in Y])
Z_bytes = b''.join([x.to_bytes(4,'big') for x in Z])

def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)

def blocks(data):
    return [data[i:(i+BLOCK_SIZE)] for i in range(0,len(data),BLOCK_SIZE)]

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

def rotate_left(data, x):
    x = x % BLOCK_SIZE
    return data[x:] + data[:x]

def rotate_right(data, x):
    x = x % BLOCK_SIZE
    return  data[-x:] + data[:-x]

def scramble_block(block):
    for _ in range(40):
        block = xor(W_bytes, block)
        block = rotate_left(block, 6)
        block = xor(X_bytes, block)
        block = rotate_right(block, 17)
    return block

def cryptohash(msg):
    initial_state = xor(Y_bytes, Z_bytes)
    msg_padded = pad(msg)
    msg_blocks = blocks(msg_padded)
    for i,b in enumerate(msg_blocks):
        mix_in = scramble_block(b)
        for _ in range(i):
            mix_in = rotate_right(mix_in, i+11)
            mix_in = xor(mix_in, X_bytes)
            mix_in = rotate_left(mix_in, i+6)
        initial_state = xor(initial_state,mix_in)
    return initial_state.hex()
```

Với chal này ta nhận thấy hàm ``pad()`` có 1 điểm yếu
```python
def pad(data):
    padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
    return data + bytes([padding_len]*padding_len)
```

Theo ta thấy thì với đoạn code này, khi đã đủ BLOCK_SIZE rồi thì nó sẽ không padding thêm vào nữa.

Ý tưởng của ta là sẽ tìm một đoạn sao cho nó sau khi padding vào sẽ ra được cùng ý với ta.

Python Implementation: 

```python
from pwn import *
import json

f = remote("socket.cryptohack.org", 13405, level = "debug")

m1 = "01" * 63
m2 = "01" * 64
payload = json.dumps({"m1": m1, "m2": m2}).encode()
f.sendlineafter(b'JSON: ', payload)
f.interactive()
```

### PriMeD5

``13392.py``
```python
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15
from Crypto.Util.number import long_to_bytes, isPrime
import math
from utils import listener
# from secrets import N, E, D

FLAG = "crypto{??????????????????}"


key = RSA.construct((N, E, D))
sig_scheme = pkcs1_15.new(key)


class Challenge():
    def __init__(self):
        self.before_input = "Primality checking is expensive so I made a service that signs primes, allowing anyone to quickly check if a number is prime\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            p = int(msg["prime"])
            if p.bit_length() > 1024:
                return {"error": "The prime is too large."}
            if not isPrime(p):
                return {"error": "You must specify a prime."}

            hash = MD5.new(long_to_bytes(p))
            sig = sig_scheme.sign(hash)
            return {"signature": sig.hex()}

        elif msg["option"] == "check":
            p = int(msg["prime"])
            sig = bytes.fromhex(msg["signature"])
            hash = MD5.new(long_to_bytes(p))
            try:
                sig_scheme.verify(hash, sig)
            except ValueError:
                return {"error": "Invalid signature."}

            a = int(msg["a"])
            if a < 1:
                return {"error": "`a` value invalid"}
            if a >= p:
                return {"error": "`a` value too large"}
            g = math.gcd(a, p)
            flag_byte = FLAG[:g]
            return {"msg": f"Valid signature. First byte of flag: {flag_byte}"}

        else:
            return {"error": "Unknown option."}


listener.start_server(port=13392)
```

Ở bài này ta sẽ sử dụng một tính chất của MD5 là:

Nếu ``m1, m2`` là 1 cặp collision thì

$$MD5(m_1||t_1) = MD5(m_2||t_2)$$

Vậy nên nếu ta có trước 1 cặp collisions ta có thể khiến cho $(m_1||t_1)$ là 1 số nguyên tố và $(m_2||t_2)$ không phải số nguyên tố

Python Implementation: 

```python
from pwn import *
import json
from Crypto.Util.number import *
from array import array
from sympy import *

f = connect('socket.cryptohack.org', 13392, level = 'debug')
input1 = array('I', [0x6165300e, 0x87a79a55, 0xf7c60bd0, 0x34febd0b, 0x6503cf04, 0x854f709e, 0xfb0fc034, 0x874c9c65, 0x2f94cc40, 0x15a12deb, 0x5c15f4a3, 0x490786bb, 0x6d658673, 0xa4341f7d, 0x8fd75920, 0xefd18d5a])

input2 = array('I', [x ^ y for x, y in zip(input1, [0, 0, 0, 0, 0, 1 << 10, 0, 0, 0, 0, 1 << 31, 0, 0, 0, 0, 0])])

input1 = bytes(input1)
input2 = bytes(input2)

prime = nextprime(bytes_to_long(input1) * 256 * 256)
nonPrime = prime - bytes_to_long(input1) * 256 * 256 + bytes_to_long(input2) * 256 * 256

f.recvuntil("\n")
f.sendline(json.dumps({"option": "sign", "prime": prime}))

data = json.loads(f.recvline())

f.sendline(json.dumps({"option": "check", "prime": nonPrime, "signature": data["signature"], "a": 751}))
f.interactive()
```

Reference Doc [Crypto_MD5_Collision](https://seedsecuritylabs.org/Labs_20.04/Files/Crypto_MD5_Collision/Crypto_MD5_Collision.pdf)
### Twin Keys

``13397.py``
```python
import os
import random
from Crypto.Hash import MD5
from utils import listener

KEY_START = b"CryptoHack Secure Safe"
FLAG = b"crypto{????????????????????????????}"


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


class SecureSafe:
    def __init__(self):
        self.magic1 = os.urandom(16)
        self.magic2 = os.urandom(16)
        self.keys = {}

    def insert_key(self, key):
        if len(self.keys) >= 2:
            return {"error": "All keyholes are already occupied"}
        if key in self.keys:
            return {"error": "This key is already inserted"}

        self.keys[key] = 0
        if key.startswith(KEY_START):
            self.keys[key] = 1

        return {"msg": f"Key inserted"}

    def unlock(self):
        if len(self.keys) < 2:
            return {"error": "Missing keys"}

        if sum(self.keys.values()) != 1:
            return {"error": "Invalid keys"}

        hashes = []
        for k in self.keys.keys():
            hashes.append(MD5.new(k).digest())

        # Encrypting the hashes with secure quad-grade XOR encryption
        # Using different randomized magic numbers to prevent the hashes
        # from ever being equal
        h1 = hashes[0]
        h2 = hashes[1]
        for i in range(2, 2**(random.randint(2, 10))):
            h1 = xor(self.magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), self.magic2)

        assert h1 != bytes(bytearray(16))

        if h1 == h2:
            return {"msg": f"The safe clicks and the door opens. Amongst its secrets you find a flag: {FLAG}"}
        return {"error": "The keys does not match"}


class Challenge():
    def __init__(self):
        self.securesafe = SecureSafe()
        self.before_input = "Can you help find our lost keys to unlock the safe?\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}
        elif your_input['option'] == 'insert_key':
            key = bytes.fromhex(your_input["key"])
            return self.securesafe.insert_key(key)
        elif your_input['option'] == 'unlock':
            return self.securesafe.unlock()
        else:
            return {"error": "Invalid option"}


listener.start_server(port=13397)
```

Trong hai key mà chúng ta phải "chèn", một key phải bắt đầu bằng "CryptoHack Secure Safe" và key còn lại không được dùng lại.

```python
    def unlock(self):
        if len(self.keys) < 2:
            return {"error": "Missing keys"}

        if sum(self.keys.values()) != 1:
            return {"error": "Invalid keys"}

        hashes = []
        for k in self.keys.keys():
            hashes.append(MD5.new(k).digest())

        # Encrypting the hashes with secure quad-grade XOR encryption
        # Using different randomized magic numbers to prevent the hashes
        # from ever being equal
        h1 = hashes[0]
        h2 = hashes[1]
        for i in range(2, 2**(random.randint(2, 10))):
            h1 = xor(self.magic1, xor(h2, xor(xor(h2, xor(h1, h2)), h2)))
            h2 = xor(xor(xor(h1, xor(xor(h2, h1), h1)), h1), self.magic2)

        assert h1 != bytes(bytearray(16))

        if h1 == h2:
            return {"msg": f"The safe clicks and the door opens. Amongst its secrets you find a flag: {FLAG}"}
        return {"error": "The keys does not match"}
```

Để h1 = h2 thì mình đã tìm trên mạng 1 tool [hashclash](https://github.com/cr-marcstevens/hashclash) thỏa mãn và get flag from server

```text
git clone https://github.com/cr-marcstevens/hashclash.git
cd hashclash
mkdir twinhex
cd twinhex

printf "CryptoHack Secure Safe000" > prefix.txt
/path/to/hashclash/scripts/poc_no.sh prefix.txt
cat collision1.bin
cat collision2.bin
```

Python Implementation: 
```python
from pwn import *
import json 
# h1 from collision1.bin
# h2 from collision2.bin
h1 = "43727970746f4861636b20536563757265205361666530309b9f2f6f86928ea091d873fc781f34f7151536db965edebf11718595c31d5f2bf832b1e9e70d49671d7fe8851d3776a20eed4a89052a47f9cbef6b8d64e6fda4fd2daf78ebed627987517d0681a6c197a830435cac27fdf523956d739543ea641dbb741f18d2496e"
h2 = "43727970746f4861636c20536563757265205361666530309b9f2f6f86928ea091d873fc781f34f7151536db965edebf11718595c31d5f2bf832b1e9e70d49671d7fe8851d3776a20eec4a89052a47f9cbef6b8d64e6fda4fd2daf78ebed627987517d0681a6c197a830435cac27fdf523956d739543ea641dbb741f18d2496e"

io = remote('socket.cryptohack.org', 13397, level = 'debug')
io.recvline()

to_send = {'option': 'insert_key', 'key': h1}
io.sendline(json.dumps(to_send).encode())
print(io.recvline())

to_send = {'option': 'insert_key', 'key': h2}
io.sendline(json.dumps(to_send).encode())
print(io.recvline())

to_send = {'option': 'unlock'}
io.sendline(json.dumps(to_send).encode())
io.interactive()
```

### No Difference

Chall này chắc hẳn chúng ta cần để ý vào ``challenge()`` sao cho khi chúng ta nhập ``a, b`` thì ``hash(a) == hash(b)`` thì server sẽ trả về flag.

```python
    def challenge(self, msg):
        a = bytes.fromhex(msg['a'])
        b = bytes.fromhex(msg['b'])
        if len(a) % 4 != 0 or len(b) % 4 != 0:
            return {"error": "Inputs must be multiple of the block length!"}
        if a == b:
            return {"error": "Identical inputs are not allowed!"}
        if hash(a) == hash(b):
            return {"flag": f"Well done, here is the flag: {FLAG}"}
        else:
            return {"error": "The hashes don't match!"}
```

Từ ngữ cảnh trên chúng ta cần phải khai thác từ ``hash()``

```python
def hash(data):
    if len(data) % 4 != 0:
        return None

    state = [16, 32, 48, 80, 80, 96, 112, 128]
    for i in range(0, len(data), 4):
        block = data[i:i+4]
        state[4] ^= block[0]
        state[5] ^= block[1]
        state[6] ^= block[2]
        state[7] ^= block[3]
        state = permute(state)
        state = substitute(state)

    for _ in range(16):
        state = permute(state)
        state = substitute(state)

    output = []
    for _ in range(2):
        output += state[4:]
        state = permute(state)
        state = substitute(state)

    return bytes(output) 
```

Bây giờ chúng ta sẽ thử với 2 chuỗi b"AAAA" và b"aaaa"

Python Implementation: 
### MD0

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
from utils import listener


FLAG = "crypto{???????????????}"


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hash(data):
    data = pad(data, 16)
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out


class Challenge():
    def __init__(self):
        self.before_input = "You'll never forge my signatures!\n"
        self.key = os.urandom(16)

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "sign":
            data = bytes.fromhex(msg["message"])
            if b"admin=True" in data:
                return {"error": "Unauthorized to sign message"}
            sig = hash(self.key + data)

            return {"signature": sig.hex()}

        elif msg["option"] == "get_flag":
            sent_sig = bytes.fromhex(msg["signature"])
            data = bytes.fromhex(msg["message"])
            real_sig = hash(self.key + data)

            if real_sig != sent_sig:
                return {"error": "Invalid signature"}

            if b"admin=True" in data:
                return {"flag": FLAG}
            else:
                return {"error": "Unauthorized to get flag"}

        else:
            return {"error": "Invalid option"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13388)
```

Ở bài này ta sẽ sử dụng Hash [Length Extension Attack](https://en.wikipedia.org/wiki/Length_extension_attack)

Như ta thấy bài này cho ta một cái ``𝑠𝑖𝑔𝑛=ℎ𝑎𝑠ℎ(𝑠𝑒𝑐𝑟𝑒𝑡+𝑑𝑎𝑡𝑎)`` với hàm hash:

```python
def hash(data):
    data = pad(data, 16)
    out = b"\x00" * 16
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out
```

Ta nhận thấy rằng nó tính toán lần lượt từng block và sử dụng kết quả ở block trước để mã hóa cho block sau

Vì thế nếu ta có được ouput của block trước thì ta có thể tính được đoạn sau mà không cần biết được ``secret``

Python Implementation: 
```python
from pwn import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, json

f = connect("socket.cryptohack.org", 13388, level = 'debug')
f.recvline()

f.sendline(json.dumps({"option": "sign", "message": ""}).encode())

sign = bytes.fromhex(json.loads(f.recvline())["signature"])

original_data = b""
append_data = b"&admin=True"
padding = pad(os.urandom(16), 16)[16:]

_data = pad(append_data, 16)
out = sign

for i in range(0, len(_data), 16):
    blk = _data[i:i + 16]
    out = xor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)

payload = json.dumps({"option": "get_flag", "message": (padding + append_data).hex(), "signature": out.hex()})
f.sendline(payload)
f.interactive()
```

PS: các bạn có thể dùng [Tool Length Extension Attack](https://kt.gy/tools.html#hash///0/)

### MDFlag

``13407.py``
```python
from itertools import cycle
from hashlib import md5
import os
from utils import listener


FLAG = b'crypto{??????????????????????????????????????}'


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class Challenge():
    def __init__(self):
        self.before_input = "Enter data\n"

    def challenge(self, msg):
        if "option" not in msg:
            return {"error": "You must send an option to this server."}

        elif msg["option"] == "message":
            data = bytes.fromhex(msg["data"])

            if len(data) < len(FLAG):
              return {"error": "Bad input"}

            salted = bxor(data, cycle(FLAG))
            return {"hash": md5(salted).hexdigest()}

        else:
            return {"error": "Invalid option"}


"""
When you connect, the 'challenge' function will be called on your JSON
input.
"""
listener.start_server(port=13407)
```

Python Implementation: 
### Mixed Up

Python Implementation: 
### Invariant

Python Implementation: 