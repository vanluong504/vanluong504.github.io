---
title: Hash Function
date: 2024-03-17 12:00:00
categories: [Cryptography]
tags: [Cryptography, Learning]
image: '/assets/image/Hash/function_hash_criptomonedas_intro.png'
math: true
---

#### Tổng quan

Trong ngành mật mã học, một Hàm băm mật mã học (Cryptographic hash function) là một hàm băm với một số tính chất bảo mật nhất định để phù hợp việc sử dụng trong nhiều ứng dụng bảo mật thông tin đa dạng, chẳng hạn như chứng thực (authentication) và kiểm tra tính nguyên vẹn của thông điệp (message integrity). Một hàm băm nhận đầu vào là một xâu ký tự dài (hay thông điệp) có độ dài tùy ý và tạo ra kết quả là một xâu ký tự có độ dài cố định, đôi khi được gọi là tóm tắt thông điệp (message digest) hoặc chữ ký số (digital fingerprint).

Các hàm băm mật mã được thiết kế để ngăn khả năng đảo ngược checksum mà chúng tạo ra trở lại văn bản gốc. Mặc dù chúng hầu như không thể bị đảo ngược, nhưng chúng không thể đảm bảo 100% việc bảo vệ dữ liệu

Đây là phiên bản đơn giản của rainbow table để cho thấy cách thức hoạt động của nó khi sử dụng hàm băm mật mã SHA-1


|Plaintext|SHA-1|
|:--|:--|
|password1|e38ad214943daad1d64c102faec29de4afe9da3d|
|ilovemydog|a25fb3505406c9ac761c8428692fbf5d5ddf1316|
|Jenny400|7d5eb0173008fe55275d12e9629eef8bdb408c1f|
|dallas1984|c1ebe6d80f4c7c087ad29d2c0dc3e059fc919da2|


#### Tính chất

Hàm băm mật mã có 6 tính chất sau:


1. Tính xác định — Deterministic: cùng một chuỗi đầu vào, hàm băm luôn trả về một kết quả giống nhau.

2. Nhanh chóng — Quick: tiêu tốn ít thời gian để tính toán giá trị băm của bất kì chuỗi đầu vào nào.

3. Hàm một chiều — One-way function: không khả thi (không thể) để tìm được giá trị chuỗi đầu vào khi biết giá trị băm của nó trừ khi thử hết tất cả các giá trị có thể.

4. Hiệu ứng lan truyền — Avalanche effect: chỉ một sự thay đổi nhỏ của message có thể thay đổi đáng kể kết quả hash đến nỗi ta không biết được mối liên hệ với kết quả hash cũ.

5. Ngăn chặn đụng độ — Collision resistant: không khả thi (không thể) để tìm được giá trị 2 chuỗi đầu vào có cùng kết quả giá trị băm.

6. Ngăn chặn tấn công tiền ảnh — Pre-image attack resistant: Một cách tấn công vào các hàm băm mật mã thường cố tìm một message có giá trị hash đã cho trước. Các hàm băm mật mã phải chống lại được kiểu tấn công này.

#### Cấu trúc phổ biến của một hàm băm

![image](/assets/image/Hash/Cautruc_hash.png)

Một hàm băm hiệu quả thường có cấu trúc được thiết kế kỹ lưỡng, giúp chuyển đổi thông tin đầu vào thành một giá trị băm an toàn và không thể đảo ngược. 

Cấu trúc này thường bao gồm các thành phần chính sau:

1. **IV – Initial Value** (Giá trị Khởi Tạo): Đây là giá trị ban đầu, thường là một chuỗi n-bit, dùng làm điểm xuất phát trong quá trình băm.

2. **f – Function** (Hàm biến đổi): Đây là hàm toán học được sử dụng để xử lý thông tin đầu vào. Hàm này cần đảm bảo tính an toàn và khó đảo ngược.

3. **CVi – Chaining Variable** (Biến Trung Gian): Là các biến lưu trữ giữa các giai đoạn của quá trình băm, giúp liên kết dữ liệu từ các khối trước đó.

4. **L** – Số Khối Đầu Vào: Đây là số lượng các khối dữ liệu được xử lý.

5. **Yi** – Các Khối Đầu Vào: Là các phần của thông điệp được chia nhỏ để xử lý.

6. **b** – Độ Dài Khối Đầu Vào: Đây là độ dài cố định của mỗi khối đầu vào, định nghĩa số bit trong mỗi khối.

7. **n** – Độ Dài của Giá Trị Băm: Độ dài cuối cùng của giá trị băm được tạo ra.

#### Ứng dụng

So với các hàm hash thông thường, hàm băm mật mã thường có xu hướng sử dụng nhiều tài nguyên tính toán hơn. Vì lí do này, các hàm băm mật mã thường chỉ được dùng trong các bối cảnh cần bảo vệ, chống thông tin giả mạo trước các đối tượng độc hại.


Sau đây là một số ứng dụng của hàm băm mật mã:


1. Kiểm tra tính toàn vẹn của message và file: bằng cách so sánh giá trị băm của message trước và sau khi truyền để xác định xem liệu có thay đổi nào đã xảy ra trong quá trình truyền hay không.

2. Xác thực mật khẩu: ta có thể lưu trữ mật khẩu bằng giá trị băm của nó để tăng tính bảo mật. Để kiểm tra, password được user đưa vào sẽ được hash và so sánh với giá trị băm đã được lưu. Để phòng chống tấn công bằng brute force, ta có thể tăng thời gian kiểm tra bằng cách sử dụng key stretching. Ngoài ra ta có thể sử dụng thêm salt để tránh trường hợp: 2 password giống nhau có kết quả lưu trữ giống nhau. Xem thêm về cách lưu trữ password tại đây.

3. Bằng chứng công việc — Proof of Work (PoW): được sử dụng trong blockchain để chống lại DOS, spam bằng cách yêu cầu một số công việc từ bên muốn truy cập. Đặc điểm chính của công việc này là: công việc phải có độ khó cao tốn nhiều thời gian (nhưng khả thi) ở phía requester nhưng lại dễ kiểm tra cho provider. Vì vậy hàm băm được sử dụng ở đây. Ví dụ công việc được đưa ra là tìm một message, sao cho giá trị băm của nó bắt đầu với 20 bit 0. Trung bình mỗi requester cần thử 2¹⁹ lần để tìm ra một message đúng.

#### Danh sách các hàm băm mật mã học

|Thuật toán|	Kích thước đầu ra (output size)|	Kích thước trạng thái trong (Internal state size)|	Kích thước khối (Block size)|	Độ dài (Length size)|	Kích thước word (Word size)|	Xung đột (Collision)|
|:--|:--|:--|:--|:--|:--|:--|
|HAVAL	|256/224/192/160/128	|256	|1024	|64	|32	|Có|
|MD2	|128	|384	|128	|Không	|8	|khả năng lớn|
|MD4	|128	|128	|512	|64	|32	|Có|
|MD5	|128	|144	|122	|88	|88	|Có|
|PANAMA	|256	|8736	|256	|No	|32	|Có lỗi|
|RIPEMD	|128	|128	|512	|64	|32	|Có|
|RIPEMD-128/256	|128/256	|128/256	|512	|64	|32	|Không|
|RIPEMD-160/320	|160/320	|160/320	|512	|64	|32	|Không|
|SHA-0	|160	|160	|512	|64	|32	|Không|
|SHA-1	|160	|160	|512	|64	|32	|Có lỗi|
|SHA-256/224	|256/224	|256	|512	|64	|32	|Không|
|SHA-512/384	|512/384	|512	|1024	|128	|64	|Không|
|Tiger(2)-192/160/128	|192/160/128	|192	|512	|64	|64	|Không|
|VEST-4/8 (hash mode)	|160/256	|256/384	|8	|80/128	|1	|Không[1]|
|VEST-16/32 (hash mode)	|320/512	|512/768	|8	|160/256	|1	|Không|
|WHIRLPOOL	|512	|512	|512	|256	|8	|Không|

#### Hash Function Attacks

Một số cách tấn công hash function như :

1. [**Collision attack**](https://en.wikipedia.org/wiki/Collision_attack)

2. [**Preimage attack**](https://en.wikipedia.org/wiki/Preimage_attack)

3. [**Birthday attack**](https://en.wikipedia.org/wiki/Birthday_attack)

4. [**Length extension attack**](https://www.bing.com/search?q=length+extension+attack&cvid=848b20e29b7d4056a65183b771c6db8c&gs_lcrp=EgZjaHJvbWUqBggBEAAYQDIGCAAQRRg5MgYIARAAGEAyBggCEAAYQDIGCAMQABhAMgYIBBAAGEAyBggFEAAYQDIGCAYQABhAMgYIBxAAGEAyBggIEAAYQNIBCDkxMTdqMGo5qAIFsAIB&FORM=ANAB01&PC=ACTS)


#### Reference

[1]. https://en.wikipedia.org/wiki/Cryptographic_hash_function

[2]. https://en.wikipedia.org/wiki/Birthday_attack

[3]. https://en.wikipedia.org/wiki/Length_extension_attack

[4]. https://en.wikipedia.org/wiki/Preimage_attack

[5]. https://medium.com/zalopay-engineering/h%C3%A0m-b%C4%83m-v%C3%A0-%E1%BB%A9ng-d%E1%BB%A5ng-ph%E1%BA%A7n-1-e82e9866dbcb

[6]. https://vi.wikipedia.org/wiki/MD5

[7]. https://en.wikipedia.org/wiki/Secure_Hash_Algorithms