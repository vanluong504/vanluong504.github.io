---
title: AES Square Attack
date: 2024-05-26 20-00-00
categories: [Cryptography]
tags: [Cryptography, Learning]
image: '/assets/image/AES/square_attack/SQUARE-11.jpg'
math: true
---

AES Square Attack là một kỹ thuật phân tích mật mã được sử dụng để tấn công các hệ mật mã khối, đặc biệt là AES (Advanced Encryption Standard). Phương pháp này là một loại tấn công vi phân, nhằm vào tính đối xứng của các hoạt động trong các vòng của thuật toán mã hóa. Khai thác vào các tính chất không đổi của các round encryption trong cipher đó

Square Attack không phải là phương pháp tấn công mạnh nhất đối với AES khi thuật toán này được thực hiện đầy đủ với tất cả các vòng mã hóa, nhưng nó đã đóng góp quan trọng trong việc hiểu rõ hơn về tính bảo mật của các thuật toán mã hóa khối.

### AES 3 Round

![image](/assets/image/AES/square_attack/SQUARE-01.jpg)

Giả xử, ta có 256 bản rõ như sau, giờ ta sẽ gọi nó là ``𝛬-set`` (``𝛬-set`` là tập hợp các bytearray phân biệt có độ dài 16 và khác nhạu tịa vị trí index được gọi là **active index**)

Đầu tiên chúng ta sẽ xor với ``first round key``
![image](/assets/image/AES/square_attack/SQUARE-03.jpg)

Sau khi tất cả các phần tử trong ``𝛬-set`` thực hiện bước này, ta vẫn sẽ thu được ``𝛬-set`` với ``active index = 0``

Chúng ta sẽ đi vào vòng đầu tiên, phép biến đổi đầu tiên là ``SubBytes``

![image](/assets/image/AES/square_attack/SQUARE-04.jpg)

Với mỗi giá trị ``i``, ``SBOX[i]`` sẽ có một giá tị duy nhất. 

Các ``non-active index`` vẫn sẽ là chính nó, ``active index`` vẫn không thay đổi. Vì vậy ta vẫn thu được ``𝛬-set``

Tiếp theo ta đến ``ShiftRow``

![image](/assets/image/AES/square_attack/SQUARE-05.jpg)

Trong bước này ta vẫn thu được ``𝛬-set`` vì các bytes chỉ đổi chỗ cho nhau

Sau đó ta nhảy đến ``MixColumns``

![image](/assets/image/AES/square_attack/SQUARE-06.jpg)

Hãy nhớ cách tính toán từ cột mới từ cột cũ

$$
\begin{bmatrix}
2a_0 + 3a_1 + 1a_2 + 1a_3\\
1a_0 + 2a_1 + 3a_2 + 1a_3\\
1a_0 + 1a_1 + 2a_2 + 3a_3\\
3a_0 + 1a_1 + 1a_2 + 2a_3
\end{bmatrix}
$$

Ta thấy với 1 byte thay đổi có thể gây ảnh hưởng đến 3 bytes còn lại trong cột đó.

Sau bước này, ta sẽ có thêm 3 active index, do mỗi byte trong kết quả thu được là tổ hợp tuyến tính giữa 4 byte, gồm 3 byte cố định và 1 byte thay đổi.

$$
\underbrace{2a_0}_\text{active} +
\underbrace{3a_1 + 1a_2 + 1a_3}_\text{constant}
$$

![image](/assets/image/AES/square_attack/SQUARE-02.jpg)

Ở cuối của first round, chúng ta có ``𝛬-set`` với ``4 active index``

Và sau khi chạy hết round 3 thì ta có được như sau

![image](/assets/image/AES/square_attack/SQUARE-08.jpg)

Khi xong round thứ 3, ta không còn thu được ``𝛬-set`` nữa. Nhưng ta có thể suy ra một tính chất như sau: Ta xor toàn bộ byte đầu của các phần tử sau khi trải qua bước ``AddRoundKey``

$$
b_1 \oplus\\
b_2 \oplus\\
\cdots\\
b_{256}
$$

Tiếp đó

$$
\begin{gather*}
2 a_{1, 0} \oplus 3 a_{1, 1} \oplus 1 a_{1, 2} \oplus 1 a_{1, 3}\\
\oplus \\
2 a_{2, 0} \oplus 3 a_{2, 1} \oplus 1 a_{2, 2} \oplus 1 a_{2, 3}\\
\oplus \\
\cdots\\
\oplus\\
2 a_{256, 0} \oplus 3 a_{256, 1} \oplus 1 a_{256, 2} \oplus 1 a_{256, 3}\\
\end{gather*}
$$

Và biến đổi ta sẽ được như sau

$$
\begin{gather*}
2 (a_{0, 0} \oplus \cdots \oplus a_{256, 0})\\
\oplus\\
3 (a_{0, 1} \oplus \cdots \oplus a_{256, 1})\\
\oplus\\
1 (a_{0, 2} \oplus \cdots \oplus a_{256, 2})\\
\oplus\\
1(a_{0, 3}\oplus \cdots \oplus a_{256, 3})
\end{gather*}
= 2 \times 0 \oplus 3 \times 0 \oplus 1 \times 0 \oplus 1 \times 0 = 0
$$

Lưu ý rằng không chỉ byte đầu, mà toàn bộ các byte còn lại cũng sẽ có tính chất này. Ta gọi tính chất này là (*) và sẽ sử dụng nó để break AES 4 round.

### AES 4 Round

Bây giờ ta hãy xem qua các bước của AES 4 Round:

![image](/assets/image/AES/square_attack/SQUARE-09.jpg)

Ta có thể tìm lại 1 byte ở vị trí i theo các cách sau
 - Generate ``𝛬-set`` với active index là i, sau đó encrypt toàn bộ các phần tử trong set. Ta gọi tập các phần tử nhận được là ``enc-𝛬-set``
 - Đoán ``roundKey[4][i] = guess`` là một giá trị từ 0-255
 - Với mỗi ``ciphertext`` trong ``enc-𝛬-set``, ta sẽ thay đổi ``ciphertext[i] = ciphertext[i] ^ roundKey[i]``. Sau đó, ciphertext mới của chúng ta sẽ đi qua 2 bước là InvShiftRows và InvSubBytes. Ta gọi tập các phần tử nhận được lúc này là ``enc2-𝛬-set`` 
 - Kiểm tra xem ``enc2-𝛬-set`` của chúng ta có thỏa mãn tính chất (*) hay không. Nếu có, guess có thể chính là giá trị ta đang cần tìm.
 - Nếu có nhiều giá trị guess thỏa mãn, ta nên regenerate ``𝛬-set`` cho đến khi chỉ tìm được duy nhất 1 giá trị thỏa mãn
 
Từ đó, ta có thể tìm được roundKey thứ 4 của Cipher, và có thể reverse được Key mà Cipher đang sử dụng.

### AES 5 Round

![image](/assets/image/AES/square_attack/SQUARE-12.jpg)

Chúng ta có thể đoán 4 byte của ``roundKey`` cuối cùng để ``reverse stat``e cho đến cuối vòng thứ 4 , ngay sau khi XOR nó với ``roundKey`` cuối, chúng ta cũng có thể đoán 4 byte của ``roundKey`` cuối để tiếp tục các byte liên quan và kết thúc bằng việc thực hiện cùng một cuộc tấn công như trước. Tổng cộng, chúng ta phải đoán 8 byte khóa phụ để bắt đầu cuộc tấn công, đây là một lượng khá lớn.

![image](/assets/image/AES/square_attack/SQUARE-13.jpg)

việc đoán 8 bytes để tìm được 1 bytes ở roundKey thứ 5 tốn quá nhiều thời gian. Vì thế, ta có thể sử dụng ý tưởng sau: Do MixColumns là hàm tuyến tính dựa trên các cột của input, nên ta có thể viết lại ciphertext khi vừa hoàn thành round 4 như sau

$$
\begin{align*}
&\text{MixColumns}(\text{state}) \oplus \text{RoundKey} \\
= &\text{MixColumns}(\text{state}) \oplus \text{MixColumns}(\text{MixColumnsInv}(\text{RoundKey})) \\
= &\text{MixColumns}(\text{state } \oplus \text{MixColumnsInv}(\text{RoundKey}))
\end{align*}
$$


Do đó, ta chỉ cần đoán 4 bytes ở ``roundKey`` cuối, cùng với 1 bytes ở ``roundKey `` thứ 4 để tìm được 1 byte ở ``roundKey`` thứ 5, tổng cộng là 5 bytes. Việc này giúp giảm đáng kể khối lượng công việc cần làm để recover key, nhưng vẫn tốn khá nhiều thời gian.

![image](/assets/image/AES/square_attack/SQUARE-14.jpg)

Cuộc tấn công này đòi hỏi nhiều nguồn tài nguyên, để cover 5bytes của key cần thử $2^{8*5} = 2^{40}$

### AES 6 Round

Để có được ``𝛬-set`` , chúng ta một lần nữa cần đoán số bytes key ( 4 bytes của first sybkey)

Tạo $2^{32}$ plaintext, tất cả đều có cùng các byte ở các vị trí không hoạt động.
Các plaintext này phải bao phủ tất cả các byte có thể trong cột byte đầu tiên, ngay trước khi thực hiện phép biến đổi MixColumns của vòng đầu tiên.

Bằng cách này, khi đưa ra dự đoán chính xác, bạn sẽ chỉ cần chọn các bản rõ có liên quan thay vì tạo lại bộ bản rõ chính xác sẽ được chuyển thành tập ``Λ`` ở đầu ra của vòng đầu tiên.

![image](/assets/image/AES/square_attack/SQUARE-15.jpg)

Đối với cuộc tấn công này, cần đoán 5 + 4 = 9 byte của subkey ở điều kiện lý tưởng. Ngoài ra chúng ta có thể phải mất $2^{8*9} = 2^{72}$.

### Reference

[1] _https://www.davidwong.fr/blockbreakers/square.html_