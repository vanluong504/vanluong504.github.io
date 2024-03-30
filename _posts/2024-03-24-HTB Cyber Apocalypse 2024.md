---
title: Hackthebox Cyber Apocalypse 2024
date: 2024-03-24 00:00:00
categories: [CTF]
tags: [CTF,HTB Cyber Apocalypse 2024]
image: /assets/image/CTF/HTB/htb_intro.jpg
math: true
---

### Dynastic

```python
from secret import FLAG
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def encrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi + i)
        c += ech
    return c

with open('output.txt', 'w') as f:
    f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
    f.write(encrypt(FLAG))

# Make sure you wrap the decrypted text with the HTB flag format :-]
# DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL
```


With this challenge, each character of the flag turns into a number. If flag[i] is not a character, print it. If it is a character, print $(m - 0x41 +i) \ mod \ 26 + 0x41$


```python
from random import randint

def to_identity_map(a):
    return ord(a) - 0x41

def from_identity_map(a):
    return chr(a % 26 + 0x41)

def decrypt(m):
    c = ''
    for i in range(len(m)):
        ch = m[i]
        if not ch.isalpha():
            ech = ch
        else:
            chi = to_identity_map(ch)
            ech = from_identity_map(chi - i)
        c += ech
    return c
flag = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"
print("HTB{" + decrypt(flag)+ "}")
```

### Makeshift

```python
from secret import FLAG

flag = FLAG[::-1]
new_flag = ''

for i in range(0, len(flag), 3):
    new_flag += flag[i+1]
    new_flag += flag[i+2]
    new_flag += flag[i]

print(new_flag)

# !?}De!e3d_5n_nipaOw_3eTR3bt4{_THB
```

The flag has the format ``HTB{`` so restoring the flag is very simple


```python
msg = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
msg = msg[::-1]
flag = ''

for i in range(0, len(msg), 3):
    flag += msg[i+1]
    flag += msg[i+2]
    flag += msg[i]

print(flag)
```

### Primary Knowledge

```python
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

n = math.prod([getPrime(1024) for _ in range(2**0)])
e = 0x10001
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')

# n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
# e = 65537
# c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215
```

With this challenge we have ``n = math.prod([getPrime(1024) for _ in range(2**0)])`` as a 1024bit prime number $\implies$ private key $d = e^{-1} \ mod \ (n-1)$

```python
from Crypto.Util.number import *

n = 144595784022187052238125262458232959109987136704231245881870735843030914418780422519197073054193003090872912033596512666042758783502695953159051463566278382720140120749528617388336646147072604310690631290350467553484062369903150007357049541933018919332888376075574412714397536728967816658337874664379646535347
e = 65537
c = 15114190905253542247495696649766224943647565245575793033722173362381895081574269185793855569028304967185492350704248662115269163914175084627211079781200695659317523835901228170250632843476020488370822347715086086989906717932813405479321939826364601353394090531331666739056025477042690259429336665430591623215

d = inverse(e, n-1)
flag = long_to_bytes(pow(c, d, n)).decode()
print(flag)
```

### Iced TEA

```python
import os
from secret import FLAG
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)



if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')

#Key : 850c1413787c389e0b34437a6828a1b2
#Ciphertext : b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843
```

This challenge we just need to rewrite the ``encrypt()`` and ``encrypt_block()`` functions to recover the flag.

The challenge has 2 options AES-ECB and AES-CBC. Since there is no IV, it is encrypted to mode AES-ECB

```python
import os
from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def decrypt(self, ciphertext):
        blocks = [ciphertext[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ciphertext), self.BLOCK_SIZE//8)]
        
        pt = b''
        if self.mode == Mode.ECB:
            for ct_block in blocks:
                pt += self.decrypt_block(ct_block)
        elif self.mode == Mode.CBC:
            X = self.IV
            for ct_block in blocks:
                dec_block = self.decrypt_block(ct_block)
                pt += self._xor(X, dec_block)
                X = ct_block
        return pt

    def decrypt_block(self, ciphertext):
        c = b2l(ciphertext)
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
        
        m0 = c >> (self.BLOCK_SIZE//2)
        m1 = c & ((1 << (self.BLOCK_SIZE//2)) - 1)

        s = self.DELTA * 32
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        
        m = (m0 << (self.BLOCK_SIZE//2)) | m1
        return l2b(m)
    
if __name__ == '__main__':
    key  = bytes.fromhex("850c1413787c389e0b34437a6828a1b2")
    Ciphertext = bytes.fromhex("b36c62d96d9daaa90634242e1e6c76556d020de35f7a3b248ed71351cc3f3da97d4d8fd0ebc5c06a655eb57f2b250dcb2b39c8b2000297f635ce4a44110ec66596c50624d6ab582b2fd92228a21ad9eece4729e589aba644393f57736a0b870308ff00d778214f238056b8cf5721a843")
    cipher = Cipher(key)
    flag = cipher.decrypt(Ciphertext)
    print(unpad(flag, 16))
```


### Blunt

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256

from secret import FLAG

import random


p = getPrime(32)
print(f'p = 0x{p:x}')

g = random.randint(1, p-1)
print(f'g = 0x{g:x}')

a = random.randint(1, p-1)
b = random.randint(1, p-1)

A, B = pow(g, a, p), pow(g, b, p)

print(f'A = 0x{A:x}')
print(f'B = 0x{B:x}')

C = pow(A, b, p)
assert C == pow(B, a, p)

# now use it as shared secret
hash = sha256()
hash.update(long_to_bytes(C))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(f'ciphertext = {encrypted}')

# p = 0xdd6cc28d
# g = 0x83e21c05
# A = 0xcfabb6dd
# B = 0xc4a21ba9
# ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'
```

with this challenge, flag are  encrypted by mode AES-CBC with ``iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'`` and $key = C = A^b \ mod \ p = B^a \ mod \ p$

I use DLP to find again a or b and get flag.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256
from sympy.ntheory.residue_ntheory import discrete_log
import random


p = 0xdd6cc28d
g = 0x83e21c05
A = 0xcfabb6dd
B = 0xc4a21ba9
ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'

a = discrete_log(p, A, g)
b = discrete_log(p, B, g)

C = pow(B, a, p)
assert C == pow(B, a, p)

# now use it as shared secret
hash = sha256()
hash.update(long_to_bytes(C))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

fl = cipher.decrypt(pad(ciphertext, 16))
print(f'found = {fl}')
```

### Arranged

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from secret import FLAG, p, b, priv_a, priv_b
F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)
A = G * priv_a
B = G * priv_b
print(A)
print(B)
C = priv_a * B
assert C == priv_b * A
# now use it as shared secret
secret = C[0]
hash = sha256()
hash.update(long_to_bytes(secret))
key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(FLAG, 16))
print(encrypted)

# (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997 : 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696 : 1)
# (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734 : 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865 : 1)
# b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'
```

Challenge provide point a, A, B, G in GF(p) and secret : FLAG, b, priv_a, priv_b , p

We need to find again p : $$y^2 = x^3 + 726x + b$$ $$Gx^3 + 726Gx + b = Gy^2 + k1p \ \ \  (1)$$ $$Ax^3 + 726Ax + b = Ay^2 + k2p \ \ \ (2)$$ $$Bx^3 + 726Bx + b = By^2 + k3p \ \ \  (3)$$

Get (1)-(2) and (1)-(3)

$$p1 = Gx^3 - Ax^3 + 726(Gx-Ax) - Gy^2 + Ay^2$$

$$p2 = Gx^3 - Bx^3 + 726(Gx-Bx) - Gy^2 + By^2$$

$\implies$ $$p = GCD(p1, p2) \ mod p$$

I use ECDLP to find priv_a or priv_b with **A = G * priv_a** and **B = G * priv_b**


```python
from sympy.ntheory.residue_ntheory import discrete_log
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from sage.all import *
import hashlib
from Crypto.Util.number import *

Ax = 6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997
Ay = 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696
Bx = 4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734
By = 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865
Gx = 926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367
Gy = 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253
Ct = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'

p1 = Gx**3 - Ax**3 + 726*Gx - 726*Ax - Gy**2 + Ay**2
p2 = Gx**3 - Bx**3 + 726*Gx - 726*Bx - Gy**2 + By**2
p = GCD(p1, p2)

aa = (Gx**3 + 726 * Gx -Gy**2)%p

for b in range(1, 10000):
    print(b)
    if p-b == aa:
        print(f"found b {b = }")
        break
        
b = 42
F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)
A = E(Ax, Ay)
B = E(Bx, By)

n_A = discrete_log(A, G, operation='+')
print(f"{n_A = }")
C = n_A * B
secret = 926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367

hash = hashlib.sha256()
hash.update(long_to_bytes(secret))

key = hash.digest()[16:32]
print(key)

iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.decrypt((Ct))
print(unpad(encrypted, 16))
```

### Partial Tenacity

```python
from secret import FLAG
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
class RSACipher:
    def __init__(self, bits):
        self.key = RSA.generate(bits)
        self.cipher = PKCS1_OAEP.new(self.key)
    
    def encrypt(self, m):
        return self.cipher.encrypt(m)
    def decrypt(self, c):
        return self.cipher.decrypt(c)
cipher = RSACipher(1024)
enc_flag = cipher.encrypt(FLAG)
with open('output.txt', 'w') as f:
    f.write(f'n = {cipher.key.n}\n')
    f.write(f'ct = {enc_flag.hex()}\n')
    f.write(f'p = {str(cipher.key.p)[::2]}\n')
    f.write(f'q = {str(cipher.key.q)[1::2]}')

# n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
# ct = 7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476
# p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
# q = 15624342005774166525024608067426557093567392652723175301615422384508274269305
```

To summarize the problem, we have this is RSA with PKCS1 padding encryption with e = 65537 and we have the leak : **p = cipher.key.p)[::2]**, **q = cipher.key.q)[1::2]**
 
![image](/assets/image/CTF/HTB/HTB_partial.png)

After google,  I found [**partial known bits**](https://eprint.iacr.org/2020/1506.pdf) and [**branch and prune attack**](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/factorization/branch_and_prune.py)


```python
from math import sqrt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct = bytes.fromhex('7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476')
p1 = 151441473357136152985216980397525591305875094288738820699069271674022167902643
q1 = 15624342005774166525024608067426557093567392652723175301615422384508274269305
pbit = ''.join(['1' if i % 2 == 0 else '0' for i in range(len(str(n)))])
qbit = ''.join(['1' if i % 2 == 1 else '0' for i in range(len(str(n)))])
# print(pbit)
# print(qbit)
p= 0
q= 0
p2, q2= p1, q1
for i in range(len(str(n))):
    if pbit[-(i+1)] == '1':
        x = 10**(i+1)
        p = 10**i * (p2 % 10) + p
        for d in range(10):
            Checkprime = 10**i * d + q
            if n % x == p * Checkprime % x:
                a = Checkprime
                b = p2 // 10
                p, q, p2= p, a, b

    else:
        x = 10**(i+1)
        q = 10**i * (q2 % 10) + q
        for d in range(10):
            Checkprime = 10**i * d + p
            if n % x == q * Checkprime % x:
                a = Checkprime
                b = q2 // 10
                p, q, q2= a, q, b

e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
key = RSA.construct((n, e, d))
flag = PKCS1_OAEP.new(key).decrypt(ct)
print(flag)
```

### Permuted

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256
from random import shuffle
from secret import a, b, FLAG
class Permutation:
    def __init__(self, mapping):
        self.length = len(mapping)
        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)
    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]
    def __mul__(self, other):
        ans = []
        for i in range(self.length):
            ans.append(self(other(i)))
        return Permutation(ans)
    def __pow__(self, power, modulo=None):
        ans = Permutation.identity(self.length)
        ctr = self
        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2
        return ans
    def __str__(self):
        return str(self.mapping)
    def identity(length):
        return Permutation(range(length))
x = list(range(50_000))
shuffle(x)
g = Permutation(x)
print('g =', g)
A = g**a
print('A =', A)
B = g**b
print('B =', B)
C = A**b
assert C.mapping == (B**a).mapping
sec = tuple(C.mapping)
sec = hash(sec)
sec = long_to_bytes(sec)
hash = sha256()
hash.update(sec)
key = hash.digest()[16:32]
iv = b"mg'g\xce\x08\xdbYN2\x89\xad\xedlY\xb9"
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(FLAG, 16))
print('c =', encrypted)

```

With this challenge, we still need to find the ``key`` again, specifically find ``priv_a`` or ``priv_b``. Reading the source, I know the math operations in this ``Permuted group``. Besides, through testing many times, I realized that the elements in this ``Permuted group`` all have their own commutation rounds, ``(order)``.

```python
 class Permutation:
    def __init__(self, mapping):
        self.length = len(mapping)
        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)
    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]
    def __mul__(self, other):
        ans = []
        for i in range(self.length):
            ans.append(self(other(i)))
        return Permutation(ans)
    def __pow__(self, power, modulo=None):
        ans = Permutation.identity(self.length)
        ctr = self
        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2
        return ans
    def __str__(self):
        return str(self.mapping)
    def identity(length):
        return Permutation(range(length))
```


Here we see it is a very simple DLP problem. Since sage has a convenient implementation of permutations for us, we shall use it to solve for ``priv_a`` and ``priv_b``.  First we check the order of ``g`` and see if it is smooth

```python
from data import g, A, B
from sage.all import*

print(len(set(A)))
print(len(set(B)))

g = PermutationGroupElement(Permutation([i+1 for i in g]))
print(g.order())
print(factor(g.order()))
# 3311019189498977856900
```
 
$$order(g) = 2^2 * 3^3 * 5^2 * 7 * 11 * 13 * 23^2 * 47 * 53 * 101 * 149 * 163 * 379$$
 

we see that the primes are extremely small, hence we can use Pohlig Hellman to solve this quite quickly.

```python
from data import g, A, B
from sage.all import*

# sage permutation
g = PermutationGroupElement(Permutation([i+1 for i in g]))
A = PermutationGroupElement(Permutation([i+1 for i in A]))
B = PermutationGroupElement(Permutation([i+1 for i in B]))

# very bad dlp implementation
o = g.order()
a = []
b = []
for p,e in factor(o):
    tg = g^(ZZ(o/p^e))
    tA = A^(ZZ(o/p^e))
    tB = B^(ZZ(o/p^e))
    for i in range(p^e):
        if tg^i==tA:
            a.append([i,p^e])
    for i in range(p^e):
        if tg^i==tB:
            b.append([i,p^e])
a = crt([i[0] for i in a],[i[1] for i in a])
b = crt([i[0] for i in b],[i[1] for i in b])
assert g^a == A
assert g^b == B
print(f"{a = }")
print(f"{b = }")

# a = 839949590738986464
# b = 828039274502849303
```

When we have ``priv_a`` and ``priv_b``, we just need to put it in the ``Permutationx class`` and get the flag 

```python
from Crypto.Util.number import *
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from hashlib import sha256
from data import g, A, B
from sage.all import*


a = 839949590738986464
b = 828039274502849303
class Permutationx:
    def __init__(self, mapping):
        self.length = len(mapping)

        assert set(mapping) == set(range(self.length))     # ensure it contains all numbers from 0 to length-1, with no repetitions
        self.mapping = list(mapping)

    def __call__(self, *args, **kwargs):
        idx, *_ = args
        assert idx in range(self.length)
        return self.mapping[idx]

    def __mul__(self, other):
        ans = []

        for i in range(self.length):
            ans.append(self(other(i)))

        return Permutationx(ans)

    def __pow__(self, power, modulo=None):
        ans = Permutationx.identity(self.length)
        ctr = self

        while power > 0:
            if power % 2 == 1:
                ans *= ctr
            ctr *= ctr
            power //= 2

        return ans

    def __str__(self):
        return str(self.mapping)

    def identity(length):
        return Permutationx(range(length))

g = Permutationx(g)
assert str(g**a) == str(A) and str(g**b) == str(B)

A, B = Permutationx(A), Permutationx(B)
C = A**b
assert C.mapping == (B**a).mapping

sec = tuple(C.mapping)
sec = hash(sec)
sec = long_to_bytes(sec)

hash = sha256()
hash.update(sec)

key = hash.digest()[16:32]
enc = b'\x89\xba1J\x9c\xfd\xe8\xd0\xe5A*\xa0\rq?!wg\xb0\x85\xeb\xce\x9f\x06\xcbG\x84O\xed\xdb\xcd\xc2\x188\x0cT\xa0\xaaH\x0c\x9e9\xe7\x9d@R\x9b\xbd'
iv = b"mg'g\xce\x08\xdbYN2\x89\xad\xedlY\xb9"

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(enc), 16).decode()
print(flag)
```

Reference :
1. [**Permutation Grey CTF 2022**](https://ariana1729.github.io/writeups/2022/GreyCTF/Permutation/2022-06-10-Permutation.html)
3. [**Cryptanalysis of a Proposal Based on the Discrete Logarithm Problem Inside Sn**](https://www.researchgate.net/publication/326514386_Cryptanalysis_of_a_Proposal_Based_on_the_Discrete_Logarithm_Problem_Inside_Sn)

### Tsayaki

```python
from tea import Cipher as TEA
from secret import IV, FLAG
import os

ROUNDS = 10

def show_menu():
    print("""
============================================================================================
|| I made this decryption oracle in which I let users choose their own decryption keys.   ||
|| I think that it's secure as the tea cipher doesn't produce collisions (?) ... Right?   ||
|| If you manage to prove me wrong 10 times, you get a special gift.                      ||
============================================================================================
""")

def run():
    show_menu()

    server_message = os.urandom(20)
    print(f'Here is my special message: {server_message.hex()}')
    
    used_keys = []
    ciphertexts = []
    for i in range(ROUNDS):
        print(f'Round {i+1}/10')
        try:
            ct = bytes.fromhex(input('Enter your target ciphertext (in hex) : '))
            assert ct not in ciphertexts

            for j in range(4):
                key = bytes.fromhex(input(f'[{i+1}/{j+1}] Enter your encryption key (in hex) : '))
                assert len(key) == 16 and key not in used_keys
                used_keys.append(key)
                cipher = TEA(key, IV)
                enc = cipher.encrypt(server_message)
                if enc != ct:
                    print(f'Hmm ... close enough, but {enc.hex()} does not look like {ct.hex()} at all! Bye...')
                    exit()
        except:
            print('Nope.')
            exit()
            
        ciphertexts.append(ct)

    print(f'Wait, really? {FLAG}')


if __name__ == '__main__':
    run()

```

Challenge use source chall ``Iced Ted``

With encrypt flag mode AES-CBC because ``IV`` has been added.

Looking at the source code, we see that IV is kept intact. With ``AES-CBC`` mode, recovering IV is very simple

  
![image](/assets/image/AES/ECB_en.png)

![image](/assets/image/AES/ECB_de.png)

![image](/assets/image/AES/CBC_en.png)

![image](/assets/image/AES/CBC_de.png)

Source to find IV

```python
from tea import Cipher as TEA
from pwn import process, remote, xor
from tea import Cipher as TEA
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from pwn import *
from enum import Enum

def decrypt_block(key, ct):
    m0 = b2l(ct[:4])
    m1 = b2l(ct[4:])
    msk = (1 << 32) - 1
    DELTA = 0x9e3779b9
    s = 0xc6ef3720

    for i in range(32):
        m1 -= ((m0 << 4) + key[2]) ^ (m0 + s) ^ ((m0 >> 5) + key[3])
        m1 &= msk
        m0 -= ((m1 << 4) + key[0]) ^ (m1 + s) ^ ((m1 >> 5) + key[1])
        m0 &= msk
        s -= DELTA

    m = ((m0 << 32) + m1) & ((1 << 64) - 1)

    return l2b(m)

f = connect("localhost", 1337)
f.recvuntil(b"Here is my special message:")
sm = bytes.fromhex(f.recvuntil(b"\n").decode())
key = b"\x00"*16
cipher = TEA(key)
cipher_ecb = cipher.encrypt(sm)
print(cipher_ecb)
f.sendlineafter(b'(in hex) : ', cipher_ecb.hex().encode())
f.sendlineafter(b'(in hex) : ', key.hex().encode())
f.recvuntil(b"but ")
cipher_cbc =  bytes.fromhex(f.recv(48).decode())
print(cipher_cbc)
dec_msg = decrypt_block(key, cipher_cbc[:8])
iv = xor(dec_msg[:8], sm[:8])
print(iv)
# b'\r\xdd\xd2w<\xf4\xb9\x08'
```

Having recovered the IV successfully, we move on to the next stage of the challenge. We have to submit four distinct keys $k_0, k_1, k_2, k_3$ such that: $$ct = E_{k_0}(M) = E_{k_1}(M) = E_{k_2}(M) = E_{k_3}(M)$$

let's take a look at the TEA encrypt_block:

```python
def encrypt_block(self, msg):
    m0 = b2l(msg[:4])
    m1 = b2l(msg[4:])
    K = self.KEY
    msk = (1 << (self.BLOCK_SIZE//2)) - 1

    s = 0
    for i in range(32):
        s += self.DELTA
        m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
        m0 &= msk
        m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
        m1 &= msk
    m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1
    return l2b(m)
```

Next we will be asked to know about [**Equivalent keys**](https://www.tayloredge.com/reference/Mathematics/VRAndem.pdf) 

```
h = 0x80000000

K0 = k0 + k1 + k2 + k3
K1 = k0 + k1 + xor(k2, h) + xor(k3, h)
K2 = xor(k0, h) + xor(k1, h) + k2 + k3
K3 = xor(k0, h) + xor(k1, h) + xor(k2, h) + xor(k3, h)
```

Example

```python
def keys(key: bytes):
    h = 0x80000000
    h = l2b(h)

    k = [key[i:i+4] for i in range(0, 16, 4)]
    K0 = k[0] + k[1] + k[2] + k[3]
    K1 = k[0] + k[1] + xor(k[2], h) + xor(k[3], h)
    K2 = xor(k[0], h) + xor(k[1], h) + k[2] + k[3]
    K3 = xor(k[0], h) + xor(k[1], h) + xor(k[2], h) + xor(k[3], h)
    
    return [K0, K1, K2, K3]


for round in range(10):
    key = (str(round) * 16).encode()
    temp = keys(key)
    print(temp)

[b'0000000000000000', b'00000000\xb0000\xb0000', b'\xb0000\xb000000000000', b'\xb0000\xb0000\xb0000\xb0000']
[b'1111111111111111', b'11111111\xb1111\xb1111', b'\xb1111\xb111111111111', b'\xb1111\xb1111\xb1111\xb1111']
[b'2222222222222222', b'22222222\xb2222\xb2222', b'\xb2222\xb222222222222', b'\xb2222\xb2222\xb2222\xb2222']
[b'3333333333333333', b'33333333\xb3333\xb3333', b'\xb3333\xb333333333333', b'\xb3333\xb3333\xb3333\xb3333']
[b'4444444444444444', b'44444444\xb4444\xb4444', b'\xb4444\xb444444444444', b'\xb4444\xb4444\xb4444\xb4444']
[b'5555555555555555', b'55555555\xb5555\xb5555', b'\xb5555\xb555555555555', b'\xb5555\xb5555\xb5555\xb5555']
[b'6666666666666666', b'66666666\xb6666\xb6666', b'\xb6666\xb666666666666', b'\xb6666\xb6666\xb6666\xb6666']
[b'7777777777777777', b'77777777\xb7777\xb7777', b'\xb7777\xb777777777777', b'\xb7777\xb7777\xb7777\xb7777']
[b'8888888888888888', b'88888888\xb8888\xb8888', b'\xb8888\xb888888888888', b'\xb8888\xb8888\xb8888\xb8888']
[b'9999999999999999', b'99999999\xb9999\xb9999', b'\xb9999\xb999999999999', b'\xb9999\xb9999\xb9999\xb9999']
```

Solution

```python
from tea import Cipher as TEA
from pwn import process, remote, xor
from tea import Cipher as TEA
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from pwn import *
from enum import Enum

f = connect("localhost", 1337)
f.recvuntil(b"Here is my special message:")
sm = bytes.fromhex(f.recvuntil(b"\n").decode())
key = b"\x00"*16

def keys(key):
    h = l2b(0x80000000)
    k = [key[i:i+4] for i in range(0, 16, 4)]
    K0 = k[0] + k[1] + k[2] + k[3]
    K1 = k[0] + k[1] + xor(k[2], h) + xor(k[3], h)
    K2 = xor(k[0], h) + xor(k[1], h) + k[2] + k[3]
    K3 = xor(k[0], h) + xor(k[1], h) + xor(k[2], h) + xor(k[3], h)
    return [K0, K1, K2, K3]

for round in range(10):
    key = (str(round) * 16).encode()
    iv = b'\r\xdd\xd2w<\xf4\xb9\x08'
    ct = TEA(key, iv).encrypt(sm)
    f.sendlineafter(b' (in hex) : ', bytes.hex(ct).encode())
    temp = keys(key)
    for k in temp: 
        f.sendlineafter(b'(in hex) : ', bytes.hex(k).encode())
    if round == 9:
        print(f.recv().decode())
        break
f.interactive()
```

### ROT128

```python
import random, os, signal
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG

ROUNDS = 3
USED_STATES = []
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i))) & (2**N - 1)
N = 128

def handler(signum, frame):
    print("\n\nToo slow, don't try to do sneaky things.")
    exit()

def validate_state(state):
    if not all(0 < s < 2**N-1 for s in user_state[-2:]) or not all(0 <= s < N for s in user_state[:4]):
        print('Please, make sure your input satisfies the upper and lower bounds.')
        return False
    
    if sorted(state[:4]) in USED_STATES:
        print('You cannot reuse the same state')
        return False
    
    if sum(user_state[:4]) < 2:
        print('We have to deal with some edge cases...')
        return False

    return True

class HashRoll:
    def __init__(self):
        self.reset_state()

    def hash_step(self, i):
        r1, r2 = self.state[2*i], self.state[2*i+1]
        return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)

    def update_state(self, state=None):
        if not state:
            self.state = [0] * 6
            self.state[:4] = [random.randint(0, N) for _ in range(4)]
            self.state[-2:] = [random.randint(0, 2**N) for _ in range(2)]
        else:
            self.state = state
    
    def reset_state(self):
        self.update_state()

    def digest(self, buffer):
        buffer = int.from_bytes(buffer, byteorder='big')
        m1 = buffer >> N
        m2 = buffer & (2**N - 1)
        self.h = b''
        for i in range(2):
            self.h += int.to_bytes(self.hash_step(i) ^ (m1 if not i else m2), length=N//8, byteorder='big')
        return self.h

print('Can you test my hash function for second preimage resistance? You get to select the state and I get to choose the message ... Good luck!')

hashfunc = HashRoll()

for _ in range(ROUNDS):
    print(f'ROUND {_+1}/{ROUNDS}!')

    server_msg = os.urandom(32)
    hashfunc.reset_state()
    server_hash = hashfunc.digest(server_msg)
    print(f'You know H({server_msg.hex()}) = {server_hash.hex()}')

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(2)

    try:
        user_state = input('Send your hash function state (format: a,b,c,d,e,f) :: ').split(',')
    except:
        exit()

    try:
        user_state = list(map(int, user_state))

        if not validate_state(user_state):
            print("The state is not valid! Try again.")
            exit()

        hashfunc.update_state(user_state)

        if hashfunc.digest(server_msg) == server_hash:
            print(f'Moving on to the next round!')
            USED_STATES.append(sorted(user_state[:4]))
        else:
            print('Not today.')
            exit()
    except:
        print("The hash function's state must be all integers.")
        exit()
    finally:
       signal.alarm(0)

print(f'Uhm... how did you do that? I thought I had cryptanalyzed it enough ... {FLAG}')
```