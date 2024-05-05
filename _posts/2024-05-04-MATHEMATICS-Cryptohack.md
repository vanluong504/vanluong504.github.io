---
title: Mathematics - Cryptohack
date: 2024-04-30 12:00:00
categories: [CTF, Cryptohack, Mathematics]
tags: [Cryptohack]
image: /assets/image/Mathematics/logo.png
math: true
---


### Find the lattice
``chal.py``
```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long
import random
import math

FLAG = b'crypto{?????????????????????}'


def gen_key():
    q = getPrime(512)
    upper_bound = int(math.sqrt(q // 2))
    lower_bound = int(math.sqrt(q // 4))
    f = random.randint(2, upper_bound)
    while True:
        g = random.randint(lower_bound, upper_bound)
        if math.gcd(f, g) == 1:
            break
    h = (inverse(f, q)*g) % q
    return (q, h), (f, g)


def encrypt(q, h, m):
    assert m < int(math.sqrt(q // 2))
    r = random.randint(2, int(math.sqrt(q // 2)))
    e = (r*h + m) % q
    return e


def decrypt(q, h, f, g, e):
    a = (f*e) % q
    m = (a*inverse(f, g)) % g
    return m


public, private = gen_key()
q, h = public
f, g = private

m = bytes_to_long(FLAG)
e = encrypt(q, h, m)

print(f'Public key: {(q,h)}')
print(f'Encrypted Flag: {e}')
```

Dựa vào hàm ``encrypt()`` ta thấy

$$e = (r * h + m) \mod q$$

Như đã thấy chúng ta đã có ``e, q, h`` việc quan trọng là tìm ra ``f,g`` để giải mã với hàm ``decrypt()``

$$h = f^{-1} * g \mod q$$

$$Fh = G + Kq$$

$$Fh - Kq = G$$

$$F(1,h) - K(0, q) = (F, G)$$

Như vậy chúng ta tìm (F, G) dựa trên bài toán SVP với Matrix

$$
\begin{bmatrix}
   0 & q \\
   1 & h
\end{bmatrix}
$$

Sage Implementation: 
```python
key = (7638232120454925879231554234011842347641017888219021175304217358715878636183252433454896490677496516149889316745664606749499241420160898019203925115292257, 2163268902194560093843693572170199707501787797497998463462129592239973581462651622978282637513865274199374452805292639586264791317439029535926401109074800)
enc = 5605696495253720664142881956908624307570671858477482119657436163663663844731169035682344974286379049123733356009125671924280312532755241162267269123486523
q = key[0]
h = key[1]

M = Matrix([[h, 1], [q, 0]])
M = M.LLL()

def decrypt(q, h, f, g, e):
    a = (f * e) % q
    m = (a * pow(f, -1, g)) % g
    return hex(m)[2:]

g = M[0][0]
f = M[0][1]

print(bytes.fromhex(decrypt(q, h, f, g, enc)))
```

### Successive Powers
Sau khi đọc đề ta có như sau

$$
\begin{cases}
t[0] * x ≡ t[1] \mod p \implies  t[0] * x \mod p == t[1] \\
t[1] * x ≡ t[2] \mod p \implies  t[1] * x \mod p == t[2] \\
t[2] * x ≡ t[3] \mod p \implies  t[2] * x \mod p == t[3] \\
t = [ 588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237] \\
\end{cases}
$$

Việc tìm p, x rất đơn giải

Python Implementation: 

```python
t = [588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237]
flag = True
for p in range(100,1000):
    for x in range(2, 1000):
        for i in range(len(t) - 1):
            if t[i] * x % p == t[i + 1]:
                flag = True
            else:
                flag = False
                break
        if flag:
            print(p, x)
            break
    if flag:
        break
```

### Roll your Own
```python
from Crypto.Util.number import getPrime
import random
from utils import listener

FLAG = 'crypto{???????????????????????????????????}'

class Challenge():
    def __init__(self):
        self.no_prompt = True
        self.q = getPrime(512)
        self.x = random.randint(2, self.q)

        self.g = None
        self.n = None
        self.h = None

        self.current_step = "SHARE_PRIME"

    def check_params(self, data):
        self.g = int(data['g'], 16)
        self.n = int(data['n'], 16)
        if self.g < 2:
            return False
        elif self.n < 2:
            return False
        elif pow(self.g,self.q,self.n) != 1:
            return False
        return True

    def check_secret(self, data):
        x_user = int(data['x'], 16)
        if self.x == x_user:
            return True
        return False

    def challenge(self, your_input):
        if self.current_step == "SHARE_PRIME":
            self.before_send = "Prime generated: "
            self.before_input = "Send integers (g,n) such that pow(g,q,n) = 1: "
            self.current_step = "CHECK_PARAMS"
            return hex(self.q)

        if self.current_step == "CHECK_PARAMS":
            check_msg = self.check_params(your_input)
            if check_msg:
                self.x = random.randint(0, self.q)
                self.h = pow(self.g, self.x, self.n)
            else:
                self.exit = True
                return {"error": "Please ensure pow(g,q,n) = 1"}

            self.before_send = "Generated my public key: "
            self.before_input = "What is my private key: "
            self.current_step = "CHECK_SECRET"

            return hex(self.h)

        if self.current_step == "CHECK_SECRET":
            self.exit = True
            if self.check_secret(your_input):
                return {"flag": FLAG}
            else:
                return {"error": "Protocol broke somewhere"}

        else:
            self.exit = True
            return {"error": "Protocol broke somewhere"}


listener.start_server(port=13403)
```

Challenge này được hiểu như sau:

1. Đầu tiên server sẽ trả về **hex(q)**

2. Tiếp đó cần gửi 2 giá trị **(g,n)** sao cho $g^q  \ mod \ n = 1$

3. Sau đó server sẽ trả lại cho user **hex(h)** với $h = g^x  \ mod \ n$

4. Và cuối cùng để get **FLAG** thì $x_{user} = x$

Bước đầu ta phải bypass qua

```python
    def check_params(self, data):
        self.g = int(data['g'], 16)
        self.n = int(data['n'], 16)
        if self.g < 2:
            return False
        elif self.n < 2:
            return False
        elif pow(self.g,self.q,self.n) != 1:
            return False
        return True
```

Chúng ta sử dụng DLP attack cụ thể ở đây là [**Paillier cryptosystem**](https://en.wikipedia.org/wiki/Paillier_cryptosystem)
 
Paillier cryptosystem exploits the fact that certain discrete logarithms can be computed easily.

For example, by binomial theorem, 
 
$$(1+n)^x = \sum_{k=0}^{x} \binom{x}{2} n^k = 1 + nx + \binom{x}{2} n^2 + higher \ powers \ of \ n$$ 

$$(1+n)^x \equiv 1 + nx \  \ mod \ \ n^2$$
 
Nếu: 
 
$$y = (1 + n)^x  \ mod \ n^2$$

Thì $$x \equiv \frac{y-1}{n} \ mod \ n$$	

Đầu tiên user cần chọn g, n sao cho 

$$g^q \mod n = 1$$

nếu $g = q + 1$ và $n = q^2$

$$g^q \mod n = 1$$ 

$$g^q \equiv 1 \mod n$$

$$(1 + q)^q \equiv 1 \mod q^2$$



Example chọn q = 5

```text
sage: 6**5 % (5**2)
1
sage: 6**5 % (5**3)
26
sage: 6**5 % (5**1)
1
sage: 6**5 % (5**2)
1
sage: 6**5 % (5**4)
276
sage: 6**5 % (5**5)
1526
sage: 6**5 % (5**6)
7776
sage:
```

Như trên đã đề cập 

$$h = g^x  \ mod \ n$$ 

$$\iff h = (1 + q)^x  \ mod \ n \equiv 1 + qx \mod n^2$$ 

$$ x = \frac{h - 1}{n}  \ mod\ n$$

Python Implementation: 

```python
 from pwn import *
import json 

f = remote('socket.cryptohack.org', 13403)
q = f.recvline().decode().strip().split(": ")[1]
q = int(q[1:-1], 0)
f.recvuntil(b"1: ")

g = q + 1 
n = q ** 2

f.sendline(json.dumps({"g": hex(g), "n": hex(n)}))
p = f.recvline().decode().strip().split(": ")[1]
p = int(p[1:-1], 0)

x = (p - 1) // q 

f.sendline(json.dumps({"x": hex(x)}))
f.recvline()
f.close()
```

# to be continued