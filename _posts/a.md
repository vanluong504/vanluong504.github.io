---
title: TamuCTF 2024 - Writeup
date: 2024-04-07 12:00:00
categories: [CTF]
tags: [CTF,TamuCTF 2024]
image: /assets/image/CTF/TamuCTF_2024/logo.png
math: true
---

### Truncated 1

{% capture public.pem %}
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA64u2qOSKwRf6GWPrq9ZX
uWqvooTq2uz/3obioiWMY2l2tLpi2Jgiq7F40t9QHLuIzcggU6bRH5Cn2gsh1DtE
UQYLMkszbp88akQqpPEa7t6leIqnT8Z4rFqj6sRpdYSQS8U2FzAzWDRvhY4oEliw
comX84WCVh8BKe38qOqN1QvhZVBY00JoUk2x/HBFNCA8VpEZIeTSKvH0Rc/Dzy5h
KoHBRaL8bBLYjhqO2PNfAkvHewJIqRyqtXXbedqqDn6vp9JX4lVcS5n/i95kQN98
JYn2RSuhTxk+v1ZHpEiSLImzc+9aOAPPtsikZPsah6JOnjDbhctfZGRn1MfFfzOd
UwIDAQAB
-----END PUBLIC KEY-----
```
{% endcapture %} {% include widgets/toggle-field.html toggle-name="public.pem" button-text="Show public.pem" toggle-text=public.pem %}

{% capture private.pem %}
```
ZXPI0zfM5EJkeooRvNr3RKQEoQKBgQD0WrYbxhBveSRYvkOV0+omfutwS6wIoCme
CYCq5MboHdZn8NDCHy+Y66b+G/GMZJewqEKQSLwHcAjKHxouneFXp6AxV0rkBWtO
RNnjXfthsWXvOgBJzGm8CJQS+xVtUpYc4l1QnYaQpc0/SClSTPG775H5DnJ8t4rK
oNQur+/pcwKBgD1BU0AjW6x+GYPXUzA0/tXQpu5XaAMxkinhiiOJWT/AExzJU8Jt
eQULJ3EDENG6acSuwMhm0WMLhQ0JG6gIejRyOBZSIqjESWGHPmkU1XbUDz0iLb1h
HTqJMAWYKWJs4RnJbx6NGJAhd2Ni4CyOGmujYpqNnp1qfZNhmcj/VOeBAoGBAJgD
stU2c9UVlTIMM7mLG1kVjlzPBtha42ko2j32k3Ol1FPXcdfCVPcaa0ockjnX/rJt
CvP9+9PYs+8iSESF/cFtS/BGMRYH9Qi9NpwHRLMzDIo2GCXRIFpVL+FbCKp5PV/8
xza2uRdVvolG2EYWDjDvym0Zusmx2YtTYI0m8ObXAoGAZ6T8aF6GAZ0s814ZfEcy
zZGrZZQ/MJ7W8ZGdU1/y+204LzfGsW+d+sTPfQPYhn03/qU3SFhP095sYzELeOOZ
3yITOftHEdMP3XffnAudgn3tBHrtu0EsVFL44H7CWe4hx3M49M0lfERD60lPwUG1
8hY5qcthSko1f1WkTgN7Rrs=
-----END PRIVATE KEY-----
```
{% endcapture %} {% include widgets/toggle-field.html toggle-name="private.pem" button-text="Show private.pem" toggle-text=private.pem %}

Challenge này chúng ta có thể đọc qua [RECOVERING A FULL PEM PRIVATE KEY WHEN HALF OF IT IS REDACTED](https://blog.cryptohack.org/twitter-secrets) và [Missing Bits](https://meashiri.github.io/ctf-writeups/posts/202311-glacierctf/#missing-bits)

Nhận thấy khi b64decode private.pem ta thu được 1 đoạn dữ liệu và 5 đoạn dữ liệu được ngăn cách bởi ``0281`` 

![image](/assets/image/CTF/TamuCTF_2024/Truncated1.png)

Ta thấy trong list thì số thứ 2 là số nguyên tố

![image](/assets/image/CTF/TamuCTF_2024/Truncated1_1.png)

Từ đó ta sẽ get flag

```python
from base64 import b64decode
import sys
from Crypto.Util.number import * 
from Crypto.PublicKey import RSA
from Crypto.Util.number import * 

with open("public.pem", "rb") as f:
    key = RSA.import_key(f.read())
    
with open('flag.txt.enc','rb') as f: 
    ct = bytes_to_long(f.read())

with open('private.pem','r') as f: 
    partial_key = f.read()
partial_key = partial_key.replace('-----END PRIVATE KEY-----','')

partial_key=(b64decode(partial_key).hex())
print(partial_key)

partial_key=(partial_key.split('0281'))
partial_key = [int(i[2:],16) for i in partial_key]

print(partial_key)

partial_key_isPrime = [isPrime(i) for i in partial_key]
print(partial_key_isPrime)

p = partial_key[1]
N = key.n
e = key.e
q = N // p 

d = inverse(e,(p-1)*(q-1))
pt = pow(ct,d,N)
print(long_to_bytes(pt))
```

### Truncated 2

{% capture public.pem %}
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy+KEz83nu2HZ1fy9jec/
twHw1bkdZJStKl9J2wIo21gvJmcr+VyUcozF8mJgZKTVBvu57GTd6PhcCjyqnbH3
KB63Nji2imT8DVzHaNVTBHu1c3jm/9dNBe6qp3SxSGozO00pE/27VOrEIRwM+595
kHIO7YKWfPbdXuSp5XyVAdX9+I1gtGNYLc+yjO5h5bwHm95Le0sW8/T/Sl2i/M5d
wlYwpidyBhIJ7WPKBcgiAe0etC9XKoA5JPmtv+U3BQ5k/75hGq6pL0vxYIS4WlU8
fij2aD3QooEQJyV+8dleXQ2q0MBKRPcQGLzuM6hFVc8DesPm3g84FiNeR+jdtNNQ
iwIDAQAB
-----END PUBLIC KEY-----
```
{% endcapture %} {% include widgets/toggle-field.html toggle-name="public.pem" button-text="Show public.pem" toggle-text=public.pem %}
``private.pem``

```
WXH2tecCgYBIlOn6LCaw4cYxztL4a+AgeoJ1HXB7AYg5Vl6T9VHfWW6dFvBVmaK/
sLuzAAZBOfOD3oXHk+BY2izOQamgOY5AvgW7m4JwP+gEFk9f9NdmI9DkxyD9cFzm
76zpeUiaizor1mMAd2mcCqjaYlDB3ohA0+Wvw024ZeBlDOCPgotJrQKBgFTU0ZgY
cNeZM05a5RdFJtKXnhTG7MdNe1lgD799tMBgSBw9OMg6pASOTGrUg6QW1DrsxY23
/ouePRFBh1OMArIskZf+Ov0jqD9umsM/q1XIR3ax3iOmBX6RxH42qyrHYArbv+tB
WdiwnYGJj5oE5HtnnL5pDa9qYFUfK4InhjN3AoGAZ2q2zPPhW9v75hq8fwVvLGjP
yDT4gGIz168dnCBLLMHsNv8y0twKQMY8UnqKBBIIkaC+j6zdCM+9CU3SEGC/TwQc
5iTOHmknFfuvRYN6WKOXbTQZJIx2aDHaRz4MZlpHOVFeHrmY9/s+y24U2nOG9kAC
zBzyXKI5PxT40b/mIGs=
-----END PRIVATE KEY-----
```

![image](/assets/image/CTF/TamuCTF_2024/Truncated2.png)

Đầu tiên là khái niệm “Tag” hiểu đơn giản là để khai báo kiểu dữ liệu

Tiếp theo là “Length” chỉ độ dài của data

Ví dụ : length: “81 80” tức là “81” nói rằng len data nằm ở 1 byte kế tiếp, đó là 0x80 = 128 => len data = 128

Khi b64decode private.pem, dựa vào bảng trên mình thấy có 3 đoạn dữ liệu ngăn cách bởi ``028180``

Nghi ngờ 2 số cuối là ``dp, dq``  mình sẽ tìm p từ dp ([weirderRSA (Pico2017) — Reconstructing RSA private key](https://medium.com/@hva314/some-basic-rsa-challenges-in-ctf-part-1-some-basic-math-on-rsa-5663fa337c27))

$$dp = d (mod (p-1))$$

$$e * d = \phi(N) + 1$$

$$e * dp = 1 (mod (p-1))$$

$$=> e*dp = kp * (p-1) + 1$$

``solved.py``
```python=
from base64 import b64decode
import sys
from Crypto.Util.number import * 
from Crypto.PublicKey import RSA
from Crypto.Util.number import * 

with open("public.pem", "rb") as f:
    key = RSA.import_key(f.read())
    
with open('flag.txt.enc','rb') as f: 
    ct = bytes_to_long(f.read())

with open('private.pem','r') as f: 
    partial_key = f.read()
partial_key = partial_key.replace('-----END PRIVATE KEY-----','')

partial_key=(b64decode(partial_key).hex())
print(partial_key)

partial_key=(partial_key.split('0281'))
partial_key = [int(i[2:],16) for i in partial_key]

print(partial_key)

dp, dq = partial_key[2], partial_key[3]
print(dp, dq)

n = key.n
e = key.e

mp = (dp * e) - 1
for i in range(2,1000000):
   p = (mp // i) + 1
   if n % p == 0:
       break
q = n//p

phi = (p-1)*(q-1)
d = inverse(e,phi)
pt = long_to_bytes(pow(ct,d,n))
print(pt)
```

### Criminal