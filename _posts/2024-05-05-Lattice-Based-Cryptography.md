---
title: Lattice Based Cryptography
date: 2024-05-05 20-00-00
categories: [Cryptography]
tags: [Cryptography, Learning]
image: '/assets/image/Lattice/Logo.gif'
math: true
---

## Lattice

Các cuộc tấn công mà chúng tôi sẽ mô tả sau cả hai đều sử dụng thuật toán giảm cơ sở mạng tinh thể Lenstra-Lenstra-Lovasz. Do đó, chúng ta cần phải hiểu mạng tinh thể là gì và tại sao thuật toán LLL này lại hữu ích như vậy. Hãy suy nghĩ về Lattices như Vector Spaces. Hãy tưởng tượng một không gian vectơ đơn giản của hai vector. Bạn có thể cộng chúng lại với nhau, nhân chúng với vô hướng (giả sử R) và nó kéo dài một không gian vector.

Cho $v_1, v_2, ...,v_n \in R^{m}$ tập hợp các vector độc lập tuyến tính. Lattice L được tạo bởi  $v_1, v_2, ...,v_n$ là tổ hợp tuyến tính với các hệ số trong tập hợp Z

$$L = \{\alpha_1v_1 + \alpha_2v_2 + ... +\alpha_nv_n : \alpha_1, \alpha_2,...,\alpha_n \in Z \}$$

Giả sử $v_1, v_2, ...,v_n$ là cơ sở cho mạng tinh thể L và $w_1, w_2, ..., w_n \in L$ là một tập hợp các vectơ khác trong L. Giống như chúng ta đã làm cho các không gian vector, chúng ta có thể viết được như sau

$$
\begin{cases}
w_1 = \alpha_{1_1}v_1 + \alpha_{1_2} + ... + \alpha_{1_n}v_n \\
w_2 = \alpha_{2_1}v_1 + \alpha_{2_2} + ... + \alpha_{2_n}v_n \\ 
\ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \vdots \\
w_n = \alpha_{n_1}v_1 + \alpha_{n_2} + ... + \alpha_{n_n}v_n
\end{cases}
$$

Ta có lattice 

$$
B = \begin{pmatrix}
\alpha_{1_1} & \alpha_{1_2} & \dots & \alpha_{1_n} \\
\alpha_{2_1} & \alpha_{2_2} & \dots & \alpha_{2_n} \\
\vdots & \vdots & \ddots & \vdots \\
\alpha_{n_1} & \alpha_{n_2} & \dots & \alpha_{n_n}
\end{pmatrix}
$$

Một số loại Lattice Based chính:

 - Ring-LWE (Learning With Errors on Rings): Ring-LWE là một hệ thống mã hóa đối xứng được xây dựng trên cơ sở bài toán tìm một vector ngắn nhất trong một mạng lưới số học trên vòng. Ring-LWE được coi là một trong những hệ thống mã hóa đầu tiên và phổ biến nhất dựa trên lý thuyết lưới.

 - NTRU (N-th degree truncated polynomial ring units): NTRU là một hệ thống mã hóa đối xứng được xây dựng trên cơ sở bài toán tìm một vector ngắn nhất trong một mạng lưới số học trên đa thức cắt bớt.

 - LWE (Learning With Errors): LWE là một hệ thống mã hóa đối xứng được xây dựng trên cơ sở bài toán tìm một vector ngắn nhất trong một mạng lưới số học đa chiều. LWE là một trong những hệ thống mã hóa đối xứng đầu tiên được xây dựng dựa trên lý thuyết lưới.

 - BLISS (Basic Lattice Signature Scheme): BLISS là một hệ thống chữ ký số dựa trên lý thuyết lưới, sử dụng các mạng lưới số học để tạo ra chữ ký số và xác thực tính hợp lệ của chữ ký số đó.

 - LPR (Lyubashevsky-Peikert-Regev): LPR là một hệ thống mã hóa đối xứng dựa trên cơ sở bài toán tìm một vector ngắn nhất trong một mạng lưới số học đa chiều. Hệ thống này được xây dựng bởi Lyubashevsky, Peikert và Regev vào năm 2010.

 - NewHope: NewHope là một hệ thống mã hóa đối xứng dựa trên cơ sở bài toán tìm một vector ngắn nhất trong một mạng lưới số học đa chiều. Nó được phát triển bởi Erdem Alkim, Léo Ducas, Thomas Pöppelmann và Peter Schwabe vào năm 2015.

 - FHEW (Fully Homomorphic Encryption with Weakened Keys): FHEW là một hệ thống mã hóa đối xứng dựa trên cơ sở bài toán tìm một vector ngắn nhất trong một mạng lưới số học đa chiều. Nó được sử dụng để tạo ra các hệ thống mã hóa đa tầng hoàn toàn đồng nhất, cho phép tính toán trên dữ liệu được mã hóa mà không cần giải mã trước.

### Lattice Problems
#### 1. Shortest Vector Problem (SVP)

- Shortest Vector Problem (SVP) là một trong những bài toán quan trọng nhất trong lý thuyết lattice, nó yêu cầu tìm kiếm vector ngắn nhất trong một lattice cho trước. Cụ thể hơn, cho một lattice L được tạo bởi một tập các vector linearly independent, SVP yêu cầu tìm một vector $v \in L$ sao cho độ dài của v là nhỏ nhất có thể.

![image](/assets/image/Lattice/SVP.png)

#### 2. Closest Vector Problem (CVP)

- Closest Vector Problem (CVP) là một trong những bài toán quan trọng nhất trong lý thuyết lattice, mục tiêu của CVP là tìm điểm trên lưới gần nhất với vector mục tiêu. Cho vectơ $w \in R^m$ không thuộc L, tìm vectơ $v \in L$ gần w nhất, tức là tìm vectơ $v \in L$ sao cho $|v - w|$ được giảm thiểu.

![image](/assets/image/Lattice/CVP.png)

### Gram Schmidt

Đây là một thuật toán để trực chuẩn hóa các vector cho trước, trong một không gian tích trong với đầu vào là một tập hợp hữu hạn các vector độc lập tuyến tính với nhau. Và tạo ra một tập hợp các vector khác đôi một vuông goc với với nhau.

![gif](/assets/image/Lattice/Gram-Schmidt.gif)

Giả sử ta có 4 vector sau

```
v1 = (4,1,3,-1)
v2 = (2,1,-3,4)
v3 = (1,0,-2,7)
v4 = (6, 2, 9, -5)
```
Tiến hành trực giao hóa theo phương pháp GS ta có

$$
\begin{matrix}
y_1 = v_1 \\
y_2 = v_2  (1)
\end{matrix}
$$

Biến đổi 1 chút, ps: dưới đây là tích vô hướng, ta biến đổi sao cho nó bằng 0

$$
\begin{matrix}
\lt y_2, y_1 \gt = \lt v_2, y_1 \gt - \lt v_2, y_1 \gt .1 = 0 \\
\lt y_2, y_1 \gt = \lt v_2, y_1 \gt - \frac{\lt v_2, y_1 \gt . \lt y_1, y_1 \gt }{\lt y_1, y_1 \gt} = 0
\end{matrix}
$$

Rút gọn vế phải và vế trái $y_1$ để biến đổi từ (1) ta sẽ có

$$y_2 = v_2 - \frac{\lt v_2, y_1 \gt.y_1}{\lt y_1, y_1 \gt} $$

Tương tự như thế ta có được

$$
\begin{matrix}
y_3 = v_3  - - \frac{\lt v_3, y_2 \gt.y_2}{\lt y_2, y_2 \gt} - \frac{\lt v_3, y_1 \gt .y_1}{\lt y_1, y_1 \gt} \\
y_4 = v_4 - \frac{\lt v_4, y_3 \gt .y_3}{\lt y_3, y_3 \gt} - \frac{\lt v_4, y_2 \gt.y_2}{\lt y_2, y_2 \gt} - \frac{\lt v_4, y_1 \gt .y_1}{\lt y_1, y_1 \gt}
\end{matrix}
$$

Công thức tổng quát

$$\boxed{y_n = v_n - \displaystyle\sum_{i=1}^{n-1} \frac{\lt x_n, y_i \gt .y_i}{\lt y_i, y_i \gt} }$$

Cơ ở trực giao

$$S = {y_1, y_2, ..., y_n}$$

Cơ sở trực chuẩn

$$_S = {\frac{y_1}{|y_1|}, \frac{y_2}{|y_2|}, ..., \frac{y_n}{|y_n|}}$$

Áp dụng vào challenge [Gram Schmidt](https://cryptohack.org/challenges/maths/) ta có


Sagemath Implementation:

``solved_1.sage``
```
v1 = vector([4, 1, 3, -1])
v2 = vector([2, 1, -3, 4])
v3 = vector([1, 0, -2, 7])
v4 = vector([6, 2, 9, -5])

y1 = v1
y2 = v2 - (y1*(v2) / y1.norm()^2) * y1
y3 = v3 - (y2*(v3) / y2.norm()^2) * y2 - (y1*(v3) / y1.norm()^2) * y1
y4 = v4 - (y3*(v4) / y3.norm()^2) * y3 - (y2*(v4) / y2.norm()^2) * y2 - (y1*(v4) / y1.norm()^2) * y1

y4[1].n(digits=5)
```

``solved_2.sage``
```
v1 = vector([4, 1, 3, -1])
v2 = vector([2, 1, -3, 4])
v3 = vector([1, 0, -2, 7])
v4 = vector([6, 2, 9, -5])

V = matrix(ZZ, [v1, v2, v3, v4])

V.gram_schmidt()

V.gram_schmidt()[0][3][1].n(digits=5)
```
### Gaussian Reduction

![image](/assets/image/Lattice/gau.png)

Đây là thuật toán để đưa hai cơ sở thành một cơ sở có các vector ngắn nhất và gần như trực giao với nhau


- Bài toán vectơ ngắn nhất (SVP) - The ``Shortest Vector Problem``: tìm vectơ khác 0 ngắn nhất trong mạng L. Nói cách khác, tìm vectơ khác 0 trong $v \in L$ sao cho $|v|$ là nhỏ nhất.


- Bài toán vectơ gần nhất (CVP) - The ``Closest Vector Problem``: Cho vectơ $w \in R^m$ không thuộc L, tìm vectơ $v \in L$ gần w nhất, tức là tìm vectơ $v \in L$ sao cho $|v - w|$ được giảm thiểu.

**Algorithm for Gaussian Lattice Reduction**

```
Loop
   (a) If ||v2|| < ||v1||, swap v1, v2
   (b) Compute m = ⌊ v1∙v2 / v1∙v1 ⌉
   (c) If m = 0, return v1, v2
   (d) v2 = v2 - m*v1
Continue Loop
```

Challenge [Gaussian Reduction](https://cryptohack.org/challenges/maths/)

Python Implementation:

```python
a = vector([846835985, 9834798552])
b = vector([87502093, 123094980])

def Gauss(v1, v2):
    while True:
        if v2.norm() < v1.norm():
            v1, v2 = v2, v1
        m =  v1.dot_product(v2) // v1.dot_product(v1)
        if m == 0:
            return v1, v2
        v2 = v2 - m*v1

c, d = Gauss(a,b)
c.dot_product(d)
```
### Lenstra Lenstra Lovász Lattice Reduction Algorithm (LLL   )

Thuật toán LLL (Lenstra-Lenstra-Lovász) là một trong những thuật toán phổ biến nhất để giải bài toán tìm vector ngắn nhất đầu tiên (SVP) trong hệ thống mã hóa dựa trên lưới (lattice-based cryptography). Thuật toán này được đặt tên theo tên ba nhà toán học là A.K. Lenstra, H.W. Lenstra, và L. Lovász, người đã đề xuất nó vào năm 1982.

![image](/assets/image/Lattice/LLL.png)

Thuật toán LLL hoạt động trên một ma trận cơ sở của lưới và có hai bước chính:

 - Bước 1: Thuật toán thực hiện một số phép biến đổi trên ma trận cơ sở của lưới để đưa nó về dạng “thuận tiện” để tính toán. Trong quá trình này, thuật toán thực hiện một số phép biến đổi trên các hàng của ma trận cơ sở để đưa các giá trị của ma trận Gram về gần đường chéo chính. Việc làm này giúp tăng hiệu quả tính toán của thuật toán.

 - Bước 2: Sau khi ma trận cơ sở của lưới đã được đưa về dạng thuận tiện, thuật toán tiến hành tìm kiếm vector ngắn nhất trong lưới. Việc tìm kiếm này được thực hiện bằng cách duyệt qua từng cột của ma trận cơ sở và thay đổi các phần tử của cột đó để giảm giá trị của vector ngắn nhất được tìm thấy trước đó. Quá trình tìm kiếm được tiếp tục cho đến khi không thể tìm được vector ngắn hơn nữa.

![image](/assets/image/Lattice/LLL_ATH.png)


### Block Korkin-Zolotarev Lattice Reduction Algorithm (BKZ)

![image](/assets/image/Lattice/BKZ.png)

## Coppersmith’s Method

### Known modulus

### Any modulus

## Knapsack Problem

## Hidden Number Problem

Hidden number problem (HNP) được giới thiệu nhằm mục đích chứng minh kết quả về tính bảo mật bit của giao thức trao đổi khóa Diﬀie-Hellman. Ở mức độ cao, HNP xử lý việc khôi phục secret “hidden” number dựa trên một số kiến thức về mối quan hệ tuyến tính của nó. Do đó, nó đương nhiên tìm thấy tính hữu ích hơn nữa trong phân tích mật mã và đặc biệt là side-channel attacks.

**to be continued**
## Reference

[1] _practical improvements on bkz algorithm pqc2022_, https://csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/practical-improvements-on-bkz-algorithm-pqc2022.pdf .

[2]

[3]

[4]

[5]

[6]

[7]