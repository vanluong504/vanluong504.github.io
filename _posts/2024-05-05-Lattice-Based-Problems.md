---
title: Lattice Based Problems
date: 2024-05-05 20-00-00
categories: [Cryptography]
tags: [Cryptography, Learning]
image: '/assets/image/Lattice/Logo.gif'
math: true
---

## Lattice

Các cuộc tấn công mà chúng tôi sẽ mô tả sau cả hai đều sử dụng thuật toán giảm cơ sở mạng tinh thể Lenstra-Lenstra-Lovasz. Do đó, chúng ta cần phải hiểu mạng tinh thể là gì và tại sao thuật toán LLL này lại hữu ích như vậy. Hãy suy nghĩ về Lattices như Vector Spaces. Hãy tưởng tượng một không gian vectơ đơn giản của hai vector. Bạn có thể cộng chúng lại với nhau, nhân chúng với vô hướng (giả sử R) và nó kéo dài một không gian vector.

### Gram Schmidt

Đây là một thuật toán để trực chuẩn hóa các vector cho trước, trong một không gian tích trong với đầu vào là một tập hợp hữu hạn các vector độc lập tuyến tính với nhau. Và tạo ra một tập hợp các vector khác đôi một vuông goc với với nhau.

![gif](https://upload.wikimedia.org/wikipedia/commons/e/ee/Gram-Schmidt_orthonormalization_process.gif)

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

## Coppersmith’s Method

### Known modulus

### Any modulus

## Knapsack Problem

## Hidden Number Problem

Hidden number problem (HNP) được giới thiệu nhằm mục đích chứng minh kết quả về tính bảo mật bit của giao thức trao đổi khóa Diﬀie-Hellman. Ở mức độ cao, HNP xử lý việc khôi phục secret “hidden” number dựa trên một số kiến thức về mối quan hệ tuyến tính của nó. Do đó, nó đương nhiên tìm thấy tính hữu ích hơn nữa trong phân tích mật mã và đặc biệt là side-channel attacks.

