---
title: Hackthebox business CTF 2024 the vault of hope - Writeup
date: 2024-05-22 00:00:00
categories: [CTF]
tags: [CTF, HTB business CTF 2024]
image: /assets/image/CTF/htb-business-ctf-2024-the-vault-of-hope/logo.png
math: true
---

### Not that random [Medium]

```python
from Crypto.Util.number import *
from Crypto.Random import random, get_random_bytes
from hashlib import sha256
from secret import FLAG

def success(s):
    print(f'\033[92m[+] {s} \033[0m')

def fail(s):
    print(f'\033[91m\033[1m[-] {s} \033[0m')

MENU = '''
Make a choice:

1. Buy flag (-500 coins)
2. Buy hint (-10 coins)
3. Play (+5/-10 coins)
4. Print balance (free)
5. Exit'''

def keyed_hash(key, inp):
    return sha256(key + inp).digest()

def custom_hmac(key, inp):
    return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)

def impostor_hmac(key, inp):
    return get_random_bytes(64)

class Casino:
    def __init__(self):
        self.player_money = 100
        self.secret_key = get_random_bytes(16)
    
    def buy_flag(self):
        if self.player_money >= 500:
            self.player_money -= 500
            success(f"Winner winner chicken dinner! Thank you for playing, here's your flag :: {FLAG}")
        else:
            fail("You broke")
    
    def buy_hint(self):
        self.player_money -= 10
        hash_input = bytes.fromhex(input("Enter your input in hex :: "))
        if random.getrandbits(1) == 0:
            print("Your output is :: " + custom_hmac(self.secret_key, hash_input).hex())
        else:
            print("Your output is :: " + impostor_hmac(self.secret_key, hash_input).hex())

    def play(self):
        my_bit = random.getrandbits(1)
        my_hash_input = get_random_bytes(32)

        print("I used input " + my_hash_input.hex())

        if my_bit == 0:
            my_hash_output = custom_hmac(self.secret_key, my_hash_input)
        else:
            my_hash_output = impostor_hmac(self.secret_key, my_hash_input)

        print("I got output " + my_hash_output.hex())

        answer = int(input("Was the output from my hash or random? (Enter 0 or 1 respectively) :: "))

        if answer == my_bit:
            self.player_money += 5
            success("Lucky you!")
        else:
            self.player_money -= 10
            fail("Wrong!")

    def print_balance(self):
        print(f"You have {self.player_money} coins.")



def main():
    print("Welcome to my online casino! Let's play a game!")
    casino = Casino()

    while casino.player_money > 0:
        print(MENU)
        option = int(input('Option: '))

        if option == 1:
            casino.buy_flag()
                
        elif option == 2:
            casino.buy_hint()
                
        elif option == 3:
            casino.play()
                
        elif option == 4:
            casino.print_balance()
            
        elif option == 5:
            print("Bye.")
            break
        
    print("The house always wins, sorry ):")

if __name__ == '__main__':
    main()
```

Đến với bài này, chúng ta sẽ cùng đi phân tích nhé.

Như trên source của bài, nó cho ta 5 option với mỗi option có chức năng như sau:

```text
MENU = '''
Make a choice:

1. Buy flag (-500 coins)
2. Buy hint (-10 coins)
3. Play (+5/-10 coins)
4. Print balance (free)
5. Exit'''
```

Ở option đầu tiên cũng là option duy nhất để server trả về flag cho ta nhưng với điều kiện tiên quyết là chúng ta phải có 500 coins (hiện tại đang có 100 coins)

Option 2 ta có như sau:

```python
def keyed_hash(key, inp):
    return sha256(key + inp).digest()

def custom_hmac(key, inp):
    return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)

def impostor_hmac(key, inp):
    return get_random_bytes(64)

def buy_hint(self):
    self.player_money -= 10
    hash_input = bytes.fromhex(input("Enter your input in hex :: "))
    if random.getrandbits(1) == 0:
        print("Your output is :: " + custom_hmac(self.secret_key, hash_input).hex())
    else:
        print("Your output is :: " + impostor_hmac(self.secret_key, hash_input).hex())
```
 - Như bạn có thể thấy chúng ta phải nhập vào một đoạn hex

 - Hàm ``buy_hint()`` sẽ random giữa 0, 1 để sử dụng ``custom_hmac(key, inp)`` và ``impostor_hmac(key, inp)`` 

 - Nếu làm hàm ``impostor_hmac(key, inp)`` thì mỗi lần chúng ta sẽ nhận được 64 bytes random

 - Còn với hàm ``custom_hmac(key, inp)`` thì ta thấy phần ``keyed_hash(key, b"Improving on the security of SHA is easy")`` này luôn cố định nên nếu chúng ta biết được nó và input thì ta hoàn đoán có thể đoán đó là hàm ``custom`` hay ``impostor``.

Đến với options 3, ta bắt đầu vào cuộc chơi, nếu đúng sẽ được 5 coin và sai thì sẽ trừ 10 coins

```python
def play(self):
    my_bit = random.getrandbits(1)
    my_hash_input = get_random_bytes(32)
    print("I used input " + my_hash_input.hex())
    if my_bit == 0:
        my_hash_output = custom_hmac(self.secret_key, my_hash_input)
    else:
        my_hash_output = impostor_hmac(self.secret_key, my_hash_input)
    print("I got output " + my_hash_output.hex())
    answer = int(input("Was the output from my hash or random? (Enter 0 or 1 respectively) :: "))
    if answer == my_bit:
        self.player_money += 5
        success("Lucky you!")
    else:
        self.player_money -= 10
        fail("Wrong!")
```

 - Ta thấy hàm này có thể chả về ngầu nhiên ``custom`` hoặc là ``impostor``

 - Chúng ta chỉ cần gửi đi ``b"Improving on the security of SHA is easy"`` thì dễ dàng có lại ``keyed_hash(key, b"Improving on the security of SHA is easy")``
 
 - Tiếp đó so sánh ``hash`` mà server trả về với hash của mình tính nếu nó thỏa mãn thì gửi lại số 0, nêu không thỏa mã thì gửi số 1.

Options 4 sẽ show điểm coins hiện tại chúng ta có

Và option cuối cùng là exit khỏi server

Python Implementation:

```python
from Crypto.Util.number import *
from pwn import *
from tqdm import tqdm
from hashlib import *

# f = connect("83.136.248.97", 35702, level = 'debug')
f = process(["python3", "server.py"])

f.recvline()
f.sendlineafter(b"Option: ", b"2")
f.recvuntil(b"Enter your input in hex :: ")
f.sendline((b"Improving on the security of SHA is easy").hex())
f.recvuntil(b"Your output is :: ")

hash_key = bytes.fromhex(f.recvline()[:-1].decode()[-64:])
print(hash)

def keyed_hash(key, inp):
    return sha256(key + inp).digest()

for i in tqdm(range(100)):
    f.sendlineafter(b"Option: ", b"3")
    f.recvuntil(b"I used input ")
    inp = bytes.fromhex(f.recvline()[:-1].decode())
    f.recvuntil(b"I got output ")
    out = bytes.fromhex(f.recvline()[:-1].decode())
    if out.startswith(keyed_hash(hash_key, inp)):
        f.sendlineafter(b":: ", str(0).encode())
    else:
        f.sendlineafter(b":: ", str(1).encode())

f.sendlineafter(b"Option: ", b"4")
f.sendlineafter(b"Option: ", b"1")
f.interactive()
```

### Blessed [Hard]

```python
import json

from eth_typing import BLSPrivateKey, BLSPubkey, BLSSignature
from secrets import randbelow
from typing import Dict, Generator, List

from Crypto.PublicKey import ECC

from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import pubkey_to_G1
from py_ecc.bls.point_compression import decompress_G1
from py_ecc.bls.typing import G1Compressed

from py_ecc.optimized_bls12_381.optimized_curve import add, curve_order, G1, multiply, neg, normalize


try:
    with open('flag.txt') as f:
        FLAG = f.read().strip()
except FileNotFoundError:
    FLAG = 'HTB{f4k3_fl4g_f0r_t3st1ng}'


def rng() -> Generator[int, None, None]:
    seed = randbelow(curve_order)
    Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    G = ECC.EccPoint(Gx, Gy, curve='p256')
    B = ECC.generate(curve='p256').pointQ
    W0 = G * seed + B
    Wn = W0

    while True:
        Wn += G
        yield Wn.x >> 32
        yield Wn.y >> 32


class Robot:
    def __init__(self, robot_id: int, verified: bool = True):
        self.robot_id: int           = robot_id
        self.verified: bool          = verified
        self.pk:       BLSPubkey     = BLSPubkey(b'')
        self._sk:      BLSPrivateKey = BLSPrivateKey(0)

        if self.verified:
            self._sk = BLSPrivateKey(randbelow(curve_order))
            self.pk = bls.SkToPk(self._sk)

    def json(self) -> Dict[str, str]:
        return {'robot_id': hex(self.robot_id)[2:], 'pk': self.pk.hex()}


class SuperComputer:
    def __init__(self, n: int):
        self.rand:   Generator[int, None, None] = rng()
        self.robots: List[Robot]                = []

        for _ in range(n):
            self.create()

    def _find_robot_by_id(self, robot_id: int) -> Robot | None:
        for r in self.robots:
            if r.robot_id == robot_id:
                return r

    def create(self) -> Dict[str, str]:
        r = Robot(next(self.rand))
        self.robots.append(r)
        return {'msg': 'Do not lose your secret key!', 'sk': hex(r._sk)[2:], **r.json()}

    def join(self, pk: BLSPubkey) -> Dict[str, str]:
        if not pk:
            return {'error': 'This command requires a public key'}

        r = Robot(next(self.rand), verified=False)
        r.pk = pk
        self.robots.append(r)
        return {'msg': 'Robot joined but not verified', 'robot_id': hex(r.robot_id)[2:]}

    def verify(self, robot_id: int) -> Dict[str, str]:
        r = self._find_robot_by_id(robot_id)

        if not r:
            return {'error': 'No robot found'}

        if r.verified:
            return {'error': 'User already verified'}

        print(json.dumps({'msg': 'Prove that you have the secret key that corresponds to your public key: pk = sk * G1'}))

        Pk = pubkey_to_G1(r.pk)

        for _ in range(64):
            C_hex = input('Take a random value x and send me C = x * pk (hex): ')
            C = decompress_G1(G1Compressed(int(C_hex, 16)))

            if next(self.rand) & 1:
                x = int(input('Give me x (hex): '), 16)

                if normalize(multiply(Pk, x)) != normalize(C):
                    return {'error': 'Proof failed!'}
            else:
                sk_x = int(input('Give me (sk + x) (hex): '), 16)

                if normalize(add(multiply(G1, sk_x), neg(Pk))) != normalize(C):
                    return {'error': 'Proof failed!'}

        r.verified = True
        return {'msg': 'Robot verified'}

    def list(self, robot_id: int, sig: BLSSignature) -> Dict[str, str] | List[Dict[str, str]]:
        if not sig:
            return {'error': 'This command requires a signature'}

        r = self._find_robot_by_id(robot_id)

        if not r:
            return {'error': 'No robot found'}

        if not bls.Verify(r.pk, b'list', sig):
            return {'error': 'Invalid signature'}

        return [r.json() for r in self.robots]

    def unveil_secrets(self, agg_sig: BLSSignature) -> Dict[str, str]:
        agg_pk = [r.pk for r in self.robots if r.verified]

        if not agg_sig:
            return {'error': 'This command requires an aggregated signature'}
        elif bls.FastAggregateVerify(agg_pk, b'unveil_secrets', agg_sig):
            return {'msg': 'Secrets have been unveiled!', 'flag': FLAG}
        else:
            return {'error': 'Invalid aggregated signature'}

    def help(self) -> Dict[str, str]:
        return {
            'help':           'Show this panel',
            'create':         'Generate a new robot, already verified',
            'join':           'Add a new robot, given a public key and a signature',
            'verify':         'Start interactive process to verify a robot given an ID',
            'list':           'Return a list of all existing robots',
            'unveil_secrets': 'Show the secrets given an aggregated signature of all registered robots',
            'exit':           'Shutdown the SuperComputer',
        }

    def run_cmd(self, data: Dict[str, str]) -> Dict[str, str] | List[Dict[str, str]]:
        cmd      = data.get('cmd')
        pk       = BLSPubkey(bytes.fromhex(data.get('pk', '')))
        sig      = BLSSignature(bytes.fromhex(data.get('sig', '')))
        robot_id = int(data.get('robot_id', '0'), 16)

        if cmd == 'create':
            return self.create()
        elif cmd == 'join':
            return self.join(pk)
        elif cmd == 'verify':
            return self.verify(robot_id)
        elif cmd == 'list':
            return self.list(robot_id, sig)
        elif cmd == 'unveil_secrets':
            return self.unveil_secrets(sig)
        elif cmd == 'exit':
            return {'error': 'exit'}

        return self.help()


def main():
    print('Welcome! You have been invited to use our SuperComputer, which is very powerful and totally secure. Only sophisticated robots are able to use it, so you need to create a robot to interact with the SuperComputer or maybe join an existing one. The key to our success is that critical operations need the approval of all registered robots. Hackers cannot beat our security!\n')

    crew = {
        'Architects/Engineers',
        'Explosives Experts/Demolition Specialists',
        'Hackers',
        'Stealth/Infiltration specialists',
        'Scavengers',
    }

    sc = SuperComputer(len(crew - {'Hackers'}))  # No hackers here...
    print(json.dumps(sc.help(), indent=2), end='\n\n')

    while True:
        res = sc.run_cmd(json.loads(input('> ')))
        print(json.dumps(res), end='\n\n')

        if 'error' in res:
            break


if __name__ == '__main__':
    main()
```

Bài này cần khá nhiều kiến thức về 

 - Elliptic Curve
 - LLL lattice reduction
 - Modular arithmetic
 - Pairing-based cryptography
 - Zero-knowlegde proofs
 - BLS signatures
 - BLS12-381 pairing-friendly elliptic curves
 - EC-LCG
