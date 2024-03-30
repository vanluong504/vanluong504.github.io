---
title: Elliptic Curve in Cryptography
date: 2024-02-23 12:00:00
categories: [Cryptography]
tags: [Cryptography, Learning]
image: '/assets/image/ECC/ECC3.gif'
math: true
---

## ELLIPTIC CURVES IN CRYPTOGRAPHY

## ELLIPTIC CURVES IN CRYPTOGRAPHY
### Đường cong Elliptic

Đường cong Elliptic là tập hợp các điểm có toạ độ $(x, y)$ thỏa mãn phương trình sau đây: $$y^2 +a_1xy + a_3y = x^3 + a_2x^2 + a_4x + a_6$$

Trên trường $F$ biểu diễn bằng phương trình Weiretrass: $$y + a_1xy + a_3y = x^3 + a_2x^2 + a_4x + a_6$$

Xét đường cong $E$ trên trường nguyên tố hữu hạn $F_p$ (p nguyên tố, p > 3) với công thức biến đổi sau: $$Y^2 = X^3 + aX + b$$

Định nghĩa: Giả sử $K$ là một trường có đặc số khác 2 và khác 3 và xét đa thức $X^3+ aX + b$ (với $a, b  \in K$). Khi đó đường con elliptic trên trường $K : Y^2 = X^3 + aX + b$ là tập hợp tất cả các điểm $(x, y)$ với $x,y \in K$ sao cho $Y^2 = X^3 + aX + b$ không có các nghiệm bội tức là $4a^3 + 27b^2 \ne 0 \ (mod \ p)$ cùng với phần tử $O$ - điểm $O$ này được gọi là $điểm \ vô \ hạn$

![image](/assets/image/ECC/ECC1.png)


2 ví dụ về đường cong elliptic


![image](/assets/image/ECC/ECC2.png)

Trong không gian 3d thì đường cong Elliptic trông như sau:
 
![gif](/assets/image/ECC/ECC3.gif)

Tính chất của đường cong Elliptic:

1. Nếu hai điểm $P_1(x_1 + y_1)$ và $P_2(x_2 + y_2)$ với $x_1 \ne x_2$ nằm trên đường cùng một đường cong Elliptic $E$ thì đường thẳng đi qua 2 điểm $P_1$ và $P_2$ sẽ cắt một điểm duy nhât $P_3(x_3, y_3)$ có thể xác định thông qua $P_1$ và $P_2$ nằm trên đường cong $E$

2. Tiếp tuyến của đường cong tại điểm bất kỳ $P(x, y)$ trên đường cong $E$ cũng cất đường cong $E$ tại một điểm duy nhất nằm trên đường $E$, điểm này cũng có thể xác định được thông qua $P$.

### Đường cong Elliptic trên trường hữu hạn

Xét trường hữu han $F_q$ của $q = p^r$ phần tử trên trường hữu hạn $K$. Giả sửu $E$ là đường cong E được định nghĩa trên $F_q$.Nếu đặc số của trường $p=2$ hoặc $p=3$ thì $E$ được cho bởi phương trình 

$$S = \lbrace (x, y) : y^{-2} + y = x^3 + ax + b \rbrace \cup \lbrace 0 \rbrace$$

$$S = \lbrace (x, y) : y^{2} = x^3 + ax + bx + c \rbrace \cup \lbrace 0 \rbrace$$


Dễ dàng thấy một đường cong như vậy có thể có nhiều nhất là $2p+1$ điểm trong $F_p$, nghĩa là điểm vô cùng với $2q$ cặp (x, y) trong đó $x, y \ \in F_q$, tức là mỗi q giá trị x có thể tồn tại nhiều nhất 2 giá trị y thỏa mãn $Y^2 = X^3 + aX + b$. Nhưng vì chỉ có một nửa các phần của $F_q^*$ có căn bậc 2 người ta kì vọng chỉ có khoảng một nửa số các điểm của $F_q$


Ví dụ : Nếu $q = p$ là 1 số nguyên tố thì $λ(x) = (x / p)$ là kí hiệu Legedre Symbol. Do đó trong tất cả mọi trường hợp số các nghiệm $y \in F_q$ thảo mãn phương trình $y^2=u$ là bằng $1+ λ(u)$. Vì vậy số các nghiệm ở phương trình 1 và điểm vô hạn là: 


Giả sử $λ(x^3 + ax + b) = +-1$

Lấy tổng ngẫu nhiên ta thấy rằng $\displaystyle\sum_{x \in Fq} (x^3 + ax + b)$ bị chặn bở $2 \sqrt{q}$ đó chính là định lý Hasses được phát triển như sau

Gọi **N** là số các điểm trên đường cong elliptic được định nghĩa trên trường $F_q$. Khi đó $|N-(q+1)| \ =< \ 2 \sqrt{q}$

### Các phép toán trên đường cong Elliptic

#### Phép cộng trên đường cong Elliptic

![gif](/assets/image/ECC/ECC4.gif)


Đường cong Elliptic có một tính chất: “Nếu hai điểm P và Q nằm trên đường cong, thì điểm P+Q cũng sẽ nằm trên đường cong”.


Điểm này được xác định như sau:


Vẽ đường thẳng nối 2 điểm P và Q, đường thẳng này sẽ cắt đường cong tại một điểm nữa

Lấy đối xứng của điểm này qua trục hoành, ta sẽ có được P+Q

Hình dưới mô tả phép cộng được tiến hành trong đường cong Elliptic:

![image](/assets/image/ECC/ECC3.png)


Nếu 3 điểm trên đường cong Elliptic là thẳng hàng, thì tổng của chúng bằng 0

Các tính chất của phép cộng trên E:

![image](/assets/image/ECC/ECC4.png)

1. $P + O = O + P = P,  \forall P \in E$
2. $P + (−P) = O, \forall P \in E$
3. $(P + Q) + R = P + (Q + R), \forall P,Q,R \in E$
4. $P + Q = Q + P, \forall P,Q \in E$
5. $P, Q$ đối xứng nhau qua trục hoành hay $Q = -P$.  Nghịch đảo của $P$ : $-P = -(x,y) = (x, -y)$

Mã giả phép cộng trên đường cong Elliptic

```
(a) If P = O, then P + Q = Q.
(b) Otherwise, if Q = O, then P + Q = P.
(c) Otherwise, write P = (x1, y1) and Q = (x2, y2).
(d) If x1 = x2 and y1 = −y2, then P + Q = O.
(e) Otherwise:
  (e1) if P ≠ Q: λ = (y2 - y1) / (x2 - x1)
  (e2) if P = Q: λ = (3x12 + a) / 2y1
(f) x3 = λ2 − x1 − x2,     y3 = λ(x1 −x3) − y1
(g) P + Q = (x3, y3)
```
#### Phép nhân trên đường cong Elliptic


Phép nhân một số nguyên $k$ với một điểm $P$ thuộc đường cong Elliptic là điểm $Q$ được xác định bằng cách cộng $k$ lần điểm $P$ và $Q \in E$: $k * P = P + P + P + ... + P$($k$ phép cộng điểm $P$)

Ví dụ trong phép toán tính $3P$, đầu tiên ta sẽ tính $2P$ bằng cách tính $P+P$.

Theo cách cộng ở bên trên, ta vẽ đường thẳng nối $P$ và $P$, ở đây chính là tiếp tuyến của đường cong, nó cắt đường cong tại điểm $-2P$, lấy đối xứng qua trục hoành ta có $2P$.

Tiếp tục vẽ đường thẳng nối giữa $2P$ và $P$, cắt đường cong tại $-3P$, lấy đối xứng ta có $3P$.

Dưới đây là hình mô tả phép nhân trong đường cong Elliptic

![image](/assets/image/ECC/ECC5.png)


Mã giả phép nhân trên đường cong Elliptic

```sage!
Input: P in E(Fp) and an integer n > 0
1. Set Q = P and R = O.
2. Loop while n > 0.
  3. If n ≡ 1 mod 2, set R = R + Q.
  4. Set Q = 2 Q and n = ⌊n/2⌋.
  5. If n > 0, continue with loop at Step 2.
6. Return the point R, which equals nP.
```

Lưu ý: Trên đường cong Elliptic không tồn tại
1. Phép nhân 2 điểm $P$ x $Q$ trên đường cong Elliptic

2. Phép chia vô hướng $Q$ : $n$ ( với $Q =nP$ ). Việc tìm số $n$ là bài toán Logarit rời rạc - một bài toán khó có thể giải được trong thời gian đa thức

### Bài toán Logarithm rời rạc


Bài toán Logarithm rời rạc trên đường cong Elliptic (ECDLP):

Cho đường cong E trên trường hữu hạn $F_q$ điểm $P \in E(F_q)$ với  bậc $n(nP = O =  ∞)$ và điểm $Q \in E(F_q)$, tìm số nguyên $k \in [0, n-1]$ sao cho $Q = kP$. Số nguyên $k$ được gọi là logarit rời rạc của $Q$ với cơ sở $P$, hay $k = log_PQ$

Việc tìm lại số $k$ là bài toán Logarit rời rạc - một bài toán khó có thể giải được trong thời gian đa thức.

Thuật toán tốt nhất hiện nay để tấn công bài toán ECDLP là sự kết hợp của thuật toán Pohlih-Hellman và Pollard's rho, thuật toán này có độ phức tạp thời gian tính toán là $O(\sqrt p)$ với $p$ là ước số nguyên tố lớn nhất của  n do đó phải chọn số n sao cho nó chia hết cho số nguyên tố $p$ lớn nhất có $\sqrt p$ đủ lớn để giải bài toán này.

Có một số phương pháp được sử dụng để xấp xỉ logarit rời rạc, bao gồm:

#### Baby-step giant-step

Phương pháp này sử dụng kỹ thuật tìm kiếm liên tục để tìm logarit rời rạc. Nói chung, phương pháp này có độ phức tạp O(sqrt(n)), n là bậc của đường cong elliptic.

Mã giả

1. Chọn m >= $\sqrt N$ và tính $mP$
2. Tính và lưu trữ danh sách $iP$ với $0 <= i < m$
3. Tính $Q - jmP$ với j = 0, 1, 2 , ..., m-1
4. if $iP = Q - jmP$ then
5.   ...    $k = i +jm \ (mod \ N)$
6.    end if
7. Quay về bước 3

Dễ dàng nhận thấy $Q = iP + jmP$ hay $Q = (i + jm)P$ từ đó $k = i + jm$. Điểm $iP$ được tính bằng cách cộng thêm $P$ vào $(i − 1)P$ và giá trị này được gọi là bước nhỏ. $Q − jmP$ được tính bằng cách cộng thêm $mP$ vào $Q − (j − 1)mP$ và giá trị nàyđược gọi là bước lớn.

#### Pollard's Rho


Phương pháp này cũng sử dụng kỹ thuật tìm kiếm liên tục để tìm logarit rời rạc. Độ phức tạp của phương pháp này phụ thuộc vào việc lựa chọn hàm băm

Thuật toán pollard's rho dựa trên cơ sở  Floyd's cycle-finding algorithm và trên sự đánh giá rằng 2 số $x, y$ đồng dư modulo p với xác suất 0.5 sau khi chọn $1.177 \sqrt p$ số ngẫu nhiên. Nếu $p$ là nhân tử của $n$ thì $1 < gcd(|x-y|, n) <= n$ từ dó $p$ là ước số của $|x-y|$ và $n$

Mã giả thuật toán

```sage!
Inputs: n, số nguyên cần phân tích; và f(x), hàm tạo số giả ngẫu nhiên modulo n

Output: một nhân tử không tầm thường (khác 1 và n) của n, hoặc không thực hiện được.

  1. x ← 2, y ← 5; d ← 1
  2. While d = 1:
     1. x ← f(x)
     2. y ← f(f(y))
     3. d ← GCD(|x − y|, n)
  3. If d = n, return không thực hiện được.
  4. Else, return d.
```

#### Pohlig-Hellman


Cho P, Q là các phần tử trong nhóm hữu hạn G bậc N. Ta muốn tìm một số nguyên k với $kP = Q$. Giả sử biết phân tích ra thừa số nguyên tố của $N$ là

$$N = \prod_i n^{e_i}_i$$


Phương pháp Pohlig - Hellman thực hiện tốt nhất nếu tất cả các ước nguyên tố của N là nhỏ. Nếu ước nguyên tố lớn nhất xấp xỉ lớn của N thì phương pháp khó áp dụng. Vì lý do này các hệ mật dựa trên logarit rời rạc thường chọn bậc của nhóm có chứa một thừa số nguyên tố lớn

Pohlig-Hellman - rút gọn các phép tính logarit rời rạc về các nhóm con nguyên tố cấp P và sử dụng Định lý số dư Trung Hoa để giải hệ đồng dư cho logarit rời rạc cấp toàn phần

Thuật toán Pohlig-Hellman hoạt động như sau:

1. Giả sử $n = q_1^{e1} * q_2^{e2} * ... * q_i^{ei}$

2. Tính $l_i = l \ mod \ q_i^{ei}$ (1<= i <= r)

3. Sử dụng định lý thặng dư trung hoa để tính $$l ≡ l_1 \ (mod \ q_1^{e1})$$ $$l ≡ l_2 \ (mod \ q_2^{e2})$$ $$...$$ $$l ≡ l_i \ (mod \ q_i^{ei})$$ 

4. Ở đây $q_1, q_2,..., q_i$ là tập hợp nguyên tố cùng nhau gồm các số nguyên dương, $gcd(q_i, q_j) = 1$. $l_1, l_2, ..., l_i$ đều là các số nguyên dương sao cho $0 <= l_i < q_i$. Số nguyên dương duy nhất l có thể được tính toán một cách hiệu quả bằng cách sử dụng Thuật toán Euclide mở rộng.
5. $l_i=z_0+z_1q^1+z_2q^2+...+z_{e-1}q^{e-1}$ , $z_i \in [0, p-1]$

6. $P_0= \frac{n}{q_i}$ và $Q_0= \frac{n}{q_i}Q$

7. Khi đó $Q_0 = lP_0 = z_0P_0$

8. ta có thể tìm $z_0$ bằng $\frac{N}{q}Q =\frac{N}{q}(z_0 + z_1q + z_2q^2 +· · ·) P = \frac{N}{q}z_oP + (z_1+z_2q)NP = z_0 \frac{N}{p}P$ (NP = ∞)

9. Tương tự như vậy ta có thể tìm $z_1, z_2, z_3 ...$


```python
sage: from sympy.ntheory.residue_ntheory import discrete_log
....: from sage.all import *
....:
....: p = 99061670249353652702595159229088680425828208953931838069069584252923270946291
....: a = 1
....: b = 4
....: E = EllipticCurve(GF(p), [a,b])
....: G = E(43190960452218023575787899214023014938926631792651638044680168600989609069200, 20971936269255296908588589778
....: 128791635639992476076894152303569022736123671173)
....: A = E.lift_x(87360200456784002948566700858113190957688355783112995047798140117594305287669)
....: B = E.lift_x(6082896373499126624029343293750138460137531774473450341235217699497602895121)
....:
....: factors, exponents = zip(*factor(E.order()))
....: primes = [factors[i] ^ exponents[i] for i in range(len(factors))][:-2]
....: dlogs = []
....: for fac in primes:
....:     t = int(G.order()) // int(fac)
....:     dlog = discrete_log(A*t,G*t,operation="+")
....:     dlogs += [dlog]
....:     print("factor: "+str(fac)+", Discrete Log: "+str(dlog))
....: l = crt(dlogs,primes)
....: print(l)
....:
factor: 7, Discrete Log: 4
factor: 11, Discrete Log: 3
factor: 17, Discrete Log: 8
factor: 191, Discrete Log: 114
factor: 317, Discrete Log: 285
factor: 331, Discrete Log: 179
factor: 5221385621, Discrete Log: 2800833577
factor: 5397618469, Discrete Log: 3393335389
15423694994465574149
sage:
```

#### Tấn công MOV

Tấn công MOV liên quan đến việc tìm các điểm độc lập tuyến tính và tính toán ghép cặp Weil để giảm ECDLP xuống trường hữu hạn thay vì nhóm điểm trên đường cong elip

Mã giả thuật toán

1. Chọn một điểm ngẫu nhiên $T \in E(F_pm)$
2. Tính bậc $M$ của $T$
3. Đặt $d = gcd(M, N)$, $T_1 = (M / d)T$. Khi đó $T_1$ có bậc $d$ chia hết cho $N$, vậy $T_1 \in E[N]$
4. Tính $S_1 = e_N(P, T_1)$ và $S_2 = e_N(P, T_2)$. Khi đó cả $S_1, S_2$ đều thuộc vào $U_d \in F_p^*m$
5. Giải bài toán logarit rời rạc $S_2 = S_1^k$ trong $F_p^*m$. Kết quả cho ta $k(mod \ N)$
6. Lặp lại với các điểm ngẫu nhiên $T$ đến khi BCNN của các số $d$ khác nhau thu được là $N$. Khi đó ta xác định được $k(mod \ N)$

Code tham khảo [mov_attack](https://github.com/merlinepedra/crypto-attacks/blob/master/attacks/ecc/mov_attack.py)

```python
import logging
import os
import sys
from math import gcd
from sage.all import *

def get_embedding_degree(q, n, max_k):
    """
    Returns the embedding degree k of an elliptic curve.
    Note: strictly speaking this function computes the Tate-embedding degree of a curve.
    In almost all cases, the Tate-embedding degree is the same as the Weil-embedding degree (also just called the "embedding degree").
    More information: Maas M., "Pairing-Based Cryptography" (Section 5.2)
    :param q: the order of the curve base ring
    :param n: the order of the base point
    :param max_k: the maximum value of embedding degree to try
    :return: the embedding degree k, or None if it was not found
    """
    for k in range(1, max_k + 1):
        if q ** k % n == 1:
            return k

    return None


def attack(P, R, max_k=6, max_tries=10):
    """
    Solves the discrete logarithm problem using the MOV attack.
    More information: Harasawa R. et al., "Comparing the MOV and FR Reductions in Elliptic Curve Cryptography" (Section 2)
    :param P: the base point
    :param R: the point multiplication result
    :param max_k: the maximum value of embedding degree to try (default: 6)
    :param max_tries: the maximum amount of times to try to find l (default: 10)
    :return: l such that l * P == R, or None if l was not found
    """
    E = P.curve()
    q = E.base_ring().order()
    n = P.order()
    assert gcd(n, q) == 1, "GCD of base point order and curve base ring order should be 1."

    logging.info("Calculating embedding degree...")
    k = get_embedding_degree(q, n, max_k)
    if k is None:
        return None

    logging.info(f"Found embedding degree {k}")
    Ek = E.base_extend(GF(q ** k))
    Pk = Ek(P)
    Rk = Ek(R)
    for i in range(max_tries):
        Q_ = Ek.random_point()
        m = Q_.order()
        d = gcd(m, n)
        Q = (m // d) * Q_
        if Q.order() != n:
            continue

        if (alpha := Pk.weil_pairing(Q, n)) == 1:
            continue

        beta = Rk.weil_pairing(Q, n)
        logging.info(f"Computing discrete_log({beta}, {alpha})...")
        l = discrete_log(beta, alpha)
        return int(l)

    return 
```

```python
#Q = k*G
# We can solve the discrete logarithm by using the following algorithm if 

"""
Most cryptosystems based on elliptic curves can be broken if you can solve the discrete logarithm problem, that is, given the point P
and rP, find the integer r.

The MOV attack uses a bilinear pairing, which (roughly speaking) is a function e
that maps two points in an elliptic curve E(Fq) to a element in the finite field Fqk, where k is the embedding degree associated with the curve. The bilinearity means that e(rP,sQ)=e(P,Q)rs for points P,Q. Therefore, if you want to compute the discrete logarithm of rP, you can instead compute u=e(P,Q) and v=e(rP,Q) for any Q. Due to bilinearity, we have that v=e(P,Q)r=ur. Now you can solve the discrete logarithm in Fqk (given ur and u, find r) in order to solve the discrete logarithm in the elliptic curve!

Usually, the embedding degree k
is very large (the same size as q), therefore transfering the discrete logarithm to Fqk won't help you. But for some curves the embedding degree is small enough (specially supersingular curves, where k<=6), and this enables the MOV attack. For example, a curve with a 256-bit q usually offers 128 bits of security (i.e. can be attacked using 2128 steps); but if it has an embedding degree 2, then we can map the discrete logarithm to the field Fq2
which offers only 60 bits of security.
In practice the attack can be simply avoided by not using curves with small embedding degree; standardized curves are safe. Since pairings also have many constructive applications, it is possible to carefully choose curves where the cost of attacking the elliptic curve itself or the mapped finite field is the same.

"""


def movAttack(G, Q):
    k = 1
    while (p**k - 1) % E.order():
        k += 1

    Ee = EllipticCurve(GF(p**k, 'y'), [a, b])

    R = Ee.random_point()
    m = R.order()
    d = gcd(m, G.order())
    B = (m // d) * R

    assert G.order() / B.order() in ZZ
    assert G.order() == B.order()

    Ge = Ee(G)
    Qe = Ee(Q)

    n = G.order()
    alpha = Ge.weil_pairing(B, n)
    beta = Qe.weil_pairing(B, n)

    print('Computing log...')
    nQ = beta.log(alpha)
    return nQ
```

### Chữ ký số ECDSA

ECDSA là viết tắt của Elliptic Curve Digital Signature Algorithm - thuật toán sinh chữ ký số dựa trên đường cong Elliptic

ECDSA được sử dụng để tạo chữ kí số cho dữ liệu, giúp chống lại sự giả mạo cũng như làm sai lệch dữ liệu, cung cấp một phương pháp xác thực mà không ảnh hưởng đến tính bảo mật của dữ liệu gốc

![image](/assets/image/ECC/ECC6.png)

#### Tạo public key


Trên đường cong elliptic ta chọn một điểm **G**(generator point)

Ta có public key là kết quả của phép nhân $$Q_A = d_A \ × \ G$$
với $d_A$ là private key là một số ngẫu nhiên.

$Q_A$ là một điểm trên đường cong elliptic

$Q_A, \ d_A$ cố định và chỉ tính được một chiều từ $d_A -> Q_A$

#### Tạo chữ ký

Chữ ký được biểu diễn bởi một cặt $(r, s)$. Để tạo ra 1 cặp $(r, s)$ đầu tiên ta sẽ chọn 1 số ngẫu nhiên k

Ta có phép nhân $$P \ = k \ × \ G$$

Khi đó ta sẽ có tọa độ điểm $P(x, \ y)$, tọa **x** của $P$ chính là **r**

Để tính được **s** ta cần hash **m** (messeage mà ta cần ký)

Khi đó ta có $$s = k^{-1}(m+d_A \ × \ r)(mod \ p)$$

#### Xác minh chữ ký

Sử dụng public key $Q_A$ cùng điểm $G$ và tin nhắn đã hash **m**

Tính nghịch đảo của **s** trong chữ ký ($s^{-1}$)

Khôi phục điểm **P** từ **G**, tin nhắn đã hash **m**, $s^{-1}$, $Q_A$  $$P = s^{-1} × m × G + s^{-1} × r × Q_A$$

Nếu tọa độ của **x** của **P(x, y)** bằng **r** thì chữ ký hợp lệ

Hay $$P = s^{-1} × m × G + s^{-1} × r × Q_A$$ $$= (m+r × d_A)×s^{-1}×G$$ $$= (m + r × d_A)×(m+r×d_A)^{-1}×(k^{-1})^{-1}×G$$ $$= k×G$$

### Trao đổi khóa ECDH

ECDH  là một giao thức trao đổi khóa dựa trên ECC. Nó được thiết kế để cung cấp một loạt các mục đích an toàn tùy theo từng ứng dụng như xác thực khóa ẩn đơn phương; xác thực khóa ẩn lẫn nhau; đảm bảo an toàn khóa đã biết và an toàn chuyển tiếp, phụ thuộc vào các yếu tố như liệu các khóa công khai có được trao đổi theo cách xác thực không và liệu cặp khóa là tạm thời hay là tĩnh (không thay đổi theo thời gian). Giao thức này cũng chính là một biến thể của giao thức Diffie-Hellman.

Alice và Bob đồng ý sử dụng một đường cong elip cụ thể E(Fp) và 1 điểm P ∈ E(Fp). Alice chọn số nguyên bí mật nA và Bob chọn số bí mật số nguyên nB . Họ tính toán các bội số liên quan $$Q_A = n_A P$$ $$Q_B = n_B P$$

Sau đó, Alice sử dụng hệ số nhân bí mật của mình để tính $n_AQ_B$ và Bob tính toán $n_BQ_A$ theo cách tương tự

Giá trị bí mật được chia sẻ là $$n_AQ_B = n_A(n_BP) = n_B(n_AP) = n_BQ_A$$

![image](/assets/image/ECC/ECC7.png)



Dễ thấy hai bên tính khóa bí mật dùng chung là bằng nhau. Alice và Bob chỉ công bố thông tin duy nhất là khóa công khai vì vậy không ai ngoại trừ bản thân họ có thể xác định được khóa riêng của mình trừ khi giải được ECDLP

Một số phương pháp tấn công đã biết trên ECDH như: Tấn công vào ECDLP hoặc ECDHP; Tấn công vào quá trình tạo khóa; Tấn công Man-in-the-middle; Tấn công vào hàm dẫn xuất khóa; Các tấn công dựa trên việc sử dụng các tham số miền không hợp lệ; Tấn công dựa trên việc sử dụng khóa công khai không hợp lệ. Ngoài ra cũng có thể xảy ra các tấn công phi mã hóa trên ECDH ví dụ “các tấn công thực thi” như tấn công dựa trên lỗi (fault-based attacks), tấn công phân tích công suất (power-analysis attacks) và tấn công phân tích thời gian (timing-analysis attacks)

## Reference
[1] https://en.wikipedia.org/wiki/Elliptic-curve_cryptography

[2] https://en.wikipedia.org/wiki/Discrete_logarithm

[3] https://risencrypto.github.io/WeilMOV/

[4] https://en.wikipedia.org/wiki/Baby-step_giant-step

[5] https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm

[6] https://ariana1729.github.io/2021/05/31/SmartAttack.html

[7] https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm

[8] https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

[9] https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman