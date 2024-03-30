---
title: RSA & Attack
date: 2024-01-13 12:00:00
categories: [Cryptography]
tags: [cryptography, Learning]
image: '/assets/image/RSA/RSA_intro.jpg'
math: true
---

# 1. RSA và các cách tấn công thường gặp của RSA

## 1. RSA

Trong mật mã học, RSA là một thuật toán mật mã hóa khóa công khai. Đây là thuật toán đầu tiên phù hợp với việc tạo ra chữ ký điện tử đồng thời với việc mã hóa. Nó đánh dấu một sự tiến bộ vượt bậc của lĩnh vực mật mã học trong việc sử dụng khóa công cộng. RSA đang được sử dụng phổ biến trong thương mại điện tử và được cho là đảm bảo an toàn với điều kiện độ dài khóa đủ lớn.

RSA thuộc nhóm hệ mã khóa công khai, dựa vào độ khó của bài toán phân tích 1 số ra thừa số nguyên tố (factoring problem). Để tạo cặp khóa Public key và Private key, Alice cần: 

Chọn 2 số nguyên tố lớn **p, q** với **p ≠ q**

Tính $$N = p* q$$

Tính giá trị hàm số Ơle 

$$φ(N) = (p-1) * (q-1)$$

Chọn 1 số **e** sao cho 

$$1 < e < φ(N) \ và \ gcd(e, φ(N)) = 1$$

Tính $$d = e^{-1} (mod φ(N))$$ , số d thỏa mãn $$ed ≡ 1 (mod φ(N))$$

Public Key gồm:

$$N  \text{ - mudulus} $$

$$e  \text{ - số mũ mã hóa} $$

Private Key gồm:

$$N  \text{ - mudulus, xuất hiện cả trong khóa công khai và bí mật} $$

$$d  \text{ - số mũ giải mã} $$

Khi Bob muốn gửi một tin nhắn M cho Alice, Bob chuyển M thành một số **m < n** theo 1 cách thỏa thuận trước. Bob sẽ tính ra bản mã **c** từ bản rõ **m** theo công thức: 

$$c = m ^ e (modN) $$

Để giải mã, Alice dùng Private Key của mình để tính ngược lại:
     
$$m = c ^ d (modN)$$

Quá trình giải mã có thể thu được **m** ban đầu là do: 

$$c ^ d ≡ (m ^ e) ^ d ≡ m ^ ed (modN) ≡ m (modN) \ hay \ m = c ^ d (mod N)$$

Độ mạnh của hệ mã RSA dựa trên việc bạn cần phân tích được n ra thừa số nguyên tố để tính d nếu muốn phá mã, và đến nay chưa có giải thuật nào hiệu quả trong thời gian đa thức giúp ta phân tích thừa số nguyên tố đối với các số lớn.

Hệ mã RSA nếu được thiết kế một cách đúng đắn với việc chọn các tham số n, p, q, e hợp lý thì sẽ rất an toàn, thế nhưng trong các bài CTF, các tham số này thường được chọn theo một cách nào đó khiến cho hệ mã yếu đi và dễ bị tấn công. Các điểm yếu thực thi của RSA sẽ được trình bày dưới đây.

### ỨNG DỤNG

Mã hóa RSA có thể được sử dụng trong một số hệ thống khác nhau. Nó có thể vận hành trong OpenSSL, wolfCrypt, cryptlib và một số thư viện mật mã khác.

RSA cũng thường được sử dụng để tạo kết nối an toàn giữa VPN client và VPN server. Theo các giao thức như OpenVPN, TLS có thể sử dụng thuật toán RSA để trao đổi key và thiết lập một kênh an toàn.

Theo truyền thống, nó được sử dụng trong TLS và cũng là thuận toán ban đầu được sử dụng trong mã hóa PGP. RSA vẫn được nhìn thấy trong một loạt các trình duyệt web, email, VPN, chat và các kênh giao tiếp khác

Mã hóa RSA đóng vai trò quan trọng trong việc thiết lập kết nối an toàn SSL/TLS và bảo vệ dữ liệu truyền tải trên mạng. 

RSA còn sử dụng để tạo chữ kí số, xác thực Certificate HTTPS.

## 2. Các cách tấn công thường gặp của RSA

### 1. Small n

Nếu n nhỏ (chiều dài n < 256 bit), ta có thể dễ dàng factorize n bằng cách brute-force số p. Chiều dài n được khuyến cáo là 1024 bit.


Kể cả khi n lớn, đôi khi factorize của n đã có sẵn trong các database online như **factordb**. Hoặc dễ dàng factorize bằng các công cụ online như [alpertron](https://www.alpertron.com/), trang web này sử dụng phương pháp Elliptic Curve Method để factorize. Vậy nên, việc đầu tiên bạn cần làm khi gặp các bài RSA là thử các trang web này trước.


Code minh họa:

```python
from Crypto.Util.number import inverse, long_to_bytes
from factordb.factordb import FactorDB

n = 742449129124467073921545687640895127535705902454369756401331
e = 3
ct = 39207274348578481322317340648475596807303160111338236677373

f = FactorDB(n)
f.connect()
[p, q] =(f.get_factor_list())

phi =(p-1) * (q-1)
d = inverse(e,phi)
decrypted = pow(ct,d,n)
print(long_to_bytes(decrypted))
```

### 2. Small e


Giả sử Alice muốn chia sẻ một tin nhắn M nhỏ (một khóa đối xứng) qua một kênh không an toàn. Cô ấy mã hóa nó bằng RSA. n được chọn từ các số nguyên tố mạnh và khá lớn nhưng cô ấy đã chọn $e = 3$.


Sẽ không có vấn đề gì nếu cô ấy sử dụng đệm nhưng rõ ràng không phải vậy. Bạn chặn tin nhắn và suy ra từ khóa công khai rằng nó được tính toán như sau: 

$$C = M^3 [n]$$


Nhưng vì nhỏ, $M^3 < n$ vì M vậy nó không bị ảnh hưởng bởi modulo. Bạn chỉ cần tính căn bậc ba của C để có được thông điệp gốc.

$$C = M ^ 3 (modN) = M^3 $$

Code minh họa: 

```python
from Crypto.Util.number import  * 
import gmpy2
# flag = b"KCSC{?????????}"
# flag = bytes_to_long(flag)

# p = getPrime(1024)
# q = getPrime(1024)
# N = p * q
# e = 3
# cipher = pow(flag, e, N)
# print(f"{cipher = }")
# print(f"{e = }")
# print(f"{N = }")

cipher = 59679191818359995370202204525552897661585191321589640897962553635418434415061564469248378765641028251799653
e = 3
N = 21401699041420490699637745290653047330524576101816966213499740906093256690308283336690577207977880719037835247336954929148296393929524033882366630989121744982271886727656590351375192671511041954445109921679571050637854777638154411655036815605211653508056048587389327700171761542697049935330646071362109506002780542377842459042871967183121240602112834334684604955288028352155338385864589982161253480083366373037953822327026444497238099073117736732812210603049033870379303953354052872102810601901739978207517492864547072321106856087371530785966468583425201265802677864617199183004080683426914054350947398717594514616183

print(long_to_bytes(gmpy2.iroot(cipher, e)[0]))
# KCSC{123456789}
```

### 3.Fermat Attack

Trong thực tế, ta cần chọn p, q có cùng độ dài bit để tạo được 1 mã RSA mạnh, tuy nhiên nếu p, q quá gần nhau thì lại tạo ra lỗ hổng bảo mật khi mà attacker có thể dễ dàng factorize n

Trong thực tế nếu: $p - q < n^{\frac{1}{4}}$ thì Fermat’s factoring algorithm có thể phân tích n 1 cách hiệu quả.

Ta có : 

$$x = \frac{p - q}{2}$$ 

$$y = \frac{p + q}{2}$$

n có thể được phân tích thừa số nguyên tố như sau: 

$$n = x^2 - y^2 = (x - y)(x + y)$$

Định lý Fermat giúp tìm p, q

Code minh họa:

```python
def isqrt(n):
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def fermat(n):
    a = isqrt(n)
    b2 = a * a - n
    b = isqrt(n)
    count = 0
    while b * b != b2:
        a = a + 1
        b2 = a * a - n
        b = isqrt(b2)
        count += 1
    p = a+b
    q = a-b
    assert n == p  *  q
    return p, q


def main():
    n = 163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013
    p, q = fermat(n)
    print(f"{p = }")
    print(f"{q = }")
    

if __name__ == '__main__':
    main()
```

### 4.Hastad Broadcast Attack

Đặt bối cảnh một mạng nội bộ sử dụng RSA làm phương thức bảo mật truyền tin. Mỗi máy tính trong mạng LAN sẽ có một bộ Public Key $(n_i, e_i)$ riêng. Giả sử rằng, quản trị viên muốn sử dụng hệ thống mã hóa đơn giản nên anh ta chọn 1 số e nhỏ (e = 3) để dùng chung cho tất cả các máy trong mạng LAN, hay nói cách khác $e_1 = e_2 = e_n = e = 3$ .

Kịch bản tấn công xảy ra nếu máy chủ gửi cùng 1 tin nhắn broadcast m đã được mã hóa thành c1, c2, ... cho nhiều máy tính trong mạng, và ta bắt được ít nhất e ciphertext c1, c2, ..., ce. Lúc này, ta sẽ có thể khôi phục lại plaintext m không mấy khó khăn.

Giả sử e = 3, đặt $M = m^3$. Nhiệm vụ của ta là giải hệ phương trình đồng dư: 


$$M ≡ c1[n1]$$

$$M ≡ c2[n2]$$

$$M ≡ c3[n3]$$


Để tìm được M thì điều kiện cần có là 

$$GCD(ni, nj) = 1$$

Ta có thể áp dụng [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem#:~:text=In%20mathematics%2C%20the%20Chinese%20remainder,are%20pairwise%20coprime%20(no%20two)). Sau khi tính được M, ta sẽ tìm lại được m (vì $m < n_i$ nên $M = m ^ 3 < N$, ta chỉ cần tính căn bậc 3 của M).

Code minh họa:

```python
from Crypto.Util.number import  * 
import gmpy2

e = 17
c1 = 5281902984460481872302011044114495295234706883691270450730514347553367729238298595829480655414548578940224329381972042327440066670142366495280771989420757877500383415087347958655409229805727133604659164018942437897797502973158822281545452793162139435644545907400047562338947483265323747272064512895032117277125123806241924006024065776471160313966595545372454577848929238063734964580623425517430922461778531674407648652147793048655534309061064293141379907098205500027275675907609664817506677507430929046690025280013453016187259205326639860958728201747428903509610925019408056231238340322831006094356755532942788059845
n1 = 16930644133133585153982116446709052721672748348204781862085225308015958369430178426924538163682833765362822077349105004445448958262188377554881412690572248052350840173351221808492539562404392378070802786671280372543130448307383633438827466178723748896312100460675703702162271014860469664170242386651584282586901993638538797099854814661924313225993112751308504309349333978398784283221774291656840002217537988653138155296055099768818584462192204413162324165236392979907684140656757898307337905401896581249560678489854415726470019798795208823138650333827337983608326844617365113983298696064210393115154759291454195692373


c2 = 6162539726286592168394448349690174616346889109160236370611851880156690694712760329744074831228591055634518601693912353931368848316889426845015738676848439972254280732503854103853320110092491469914385988167410727536596346306843876822277027093518743294669965911466013487176645544303209199706511600822221896442247998987128724332167832065101628368630622196780631151950624374003738598234457262104177776394340556855566300326141831504301005520835753870827859262212652975658548934416777300952082762384420499635206417089278284976520806511553990747668508907624111161554742592764211574031473657602849178212391109386523736123225
n2 = 24517830966075068901143081428136123787052462312728921454664505259135368205967208384321697479280273940725987122343582634769573313694977955351008895829262278664950511633319526458471500717719183843537956381037748017055977477231213564700962749046423150919990089564077863308748604142838798184581851355965003040482172222846012964383746163017000648375552920723819402398890728926342009527890326964300454951835432280426955033831895830700954905020816313887830291466080919961631523098068933610444428612902610455365013948374770977767001367985317420877941833498437819340406382755518088589696697321340723109560066075801867816757243

c3 = 19908100167530216645294949759783346545029235701853013289113833267209207614808513713310237969750220599230702392524311814340229834745985200556448477263767965831011135495482388430411710703857335313563121388465470530848661415361605517365926771165709472561083643203337808374724449086723593596845700498749711885216543551227316982638103624172386677548005428618414955857762672903247827644153128066936494858165396265940016365364770664110861333303512475064549820159646008318554658964484061481333613199128577346633337396079262450825350654019895506969392774300773381808489530831368833223045245411050842234360325298418088989859161
n3 = 21404493333459773651833468889494854452146341909489290362795042422081025549394197696207194740465796006865793114554826965350325270688131352372790308281188594067594092027310514703330195829475266538616467239956851153498522500671756355728397676054553313625727693338831805978536697927429324389373252910725919888390839180105695354495463820979707332963584951628592768362598994748878184136661630763266935396207706143788599547556573680129113171095202415059427609744739187238102875459200266914230437205151399301939429262300637643779611482708303062671827115951463353597025183123730487168755528498188468405928192815431774026410657



N=n1 * n2 * n3
N1=N//n1
N2=N//n2
N3=N//n3

u1 = inverse(N1, n1) 
u2 = inverse(N2, n2)
u3 = inverse(N3, n3)

M = (c1 * u1 * N1 + c3 * u3 * N3 + c2 * u2 * N2) % N
m = gmpy2.iroot(M,e)[0]
print(long_to_bytes(m))
```

### 5.Wiener Attack

Để giảm thời gian giải mã (hoặc thời gian tạo chữ ký), người ta có thể muốn sử dụng một giá trị nhỏ của d hơn là một d ngẫu nhiên. Do lũy thừa mô-đun cần có thời gian tuyến tính trong log2 d, nên một d nhỏ có thể cải thiện hiệu suất ít nhất là hệ số 10 (đối với mô-đun 1024 bit). Thật không may, một cuộc tấn công thông minh của M. Wiener [19] cho thấy rằng một d nhỏ dẫn đến sự phá vỡ hoàn toàn hệ thống mật mã.

Đặt $N= p * q$ với $q < p < 2q$ . Đặt $d < \frac{1}{3}N^{\frac{1}{4}}$. Cho trước (N,e) với $ed = 1 mod \phi(N)$ , Marvin có thể phục hồi d một cách hiệu quả.

Bằng chứng dựa trên các xấp xỉ sử dụng các phân số liên tục. Vì $ed = 1 mod \phi(N)$, nên tồn tại k sao cho $ed − k \phi(N) = 1$. Do đó, $\mid \frac{e}{\phi(N)} - \frac{k}{d} \mid = \frac{1}{d.\phi(N)}$

Do đó, $\frac{k}{d}$ là một xấp xỉ của $\frac{e}{phi(N)}$. Mặc dù Marvin không biết phi(N), anh ấy có thể sử dụng N để tính gần đúng nó. Thật vậy, vì $\phi(N) = N − p − q + 1$ và $p + q − 1 < 3 \sqrt{N}$ , nên chúng ta có 
$$|N − \phi(N)| < 3 \sqrt{N}$$ 

Sử dụng N thay cho $\phi(N)$, chúng tôi thu được

Bây giờ, $k * \phi(N) = ed − 1 < ed$ . Vì $e < phi(N)$ , chúng ta thấy rằng $k < d < \frac{1}{3}N^{\frac{1}{4}}$ . Do đó chúng tôi có được


Cuối cùng có được

$\mid \frac{e}{n} - \frac{k}{d} \mid < \frac{1}{2d^2}$


Đây là một quan hệ xấp xỉ cổ điển. Các số lượng phân số $\frac{k}{d}$ với d < N gần đúng với $\frac{e}{N}$ bị giới hạn bởi $log_2N$. Thực tế, tất cả các phân số như vậy thu được dưới dạng các phần tử hội tụ của khai triển phân số liên tục của $\frac{e}{N}$ . Tất cả người ta phải làm là tính log N hội tụ của phân số tiếp tục cho $\frac{e}{N}$. Một trong số này sẽ bằng $\frac{k}{d}$. Vì $ed − kphi(N) = 1$, nên ta có $gcd(k, d) = 1$, và do đó $\frac{k}{d}$ là phân số rút gọn. Đây là một thuật toán thời gian tuyến tính để khôi phục khóa bí mật d.

Code minh họa:

```python
from Crypto.Util.number import * 
import owiener
N = 'b12746657c720a434861e9a4828b3c89a6b8d4a1bd921054e48d47124dbcc9cfcdcc39261c5e93817c167db818081613f57729e0039875c72a5ae1f0bc5ef7c933880c2ad528adbc9b1430003a491e460917b34c4590977df47772fab1ee0ab251f94065ab3004893fe1b2958008848b0124f22c4e75f60ed3889fb62e5ef4dcc247a3d6e23072641e62566cd96ee8114b227b8f498f9a578fc6f687d07acdbb523b6029c5bbeecd5efaf4c4d35304e5e6b5b95db0e89299529eb953f52ca3247d4cd03a15939e7d638b168fd00a1cb5b0cc5c2cc98175c1ad0b959c2ab2f17f917c0ccee8c3fe589b4cb441e817f75e575fc96a4fe7bfea897f57692b050d2b'
E = '9d0637faa46281b533e83cc37e1cf5626bd33f712cc1948622f10ec26f766fb37b9cd6c7a6e4b2c03bce0dd70d5a3a28b6b0c941d8792bc6a870568790ebcd30f40277af59e0fd3141e272c48f8e33592965997c7d93006c27bf3a2b8fb71831dfa939c0ba2c7569dd1b660efc6c8966e674fbe6e051811d92a802c789d895f356ceec9722d5a7b617d21b8aa42dd6a45de721953939a5a81b8dffc9490acd4f60b0c0475883ff7e2ab50b39b2deeedaefefffc52ae2e03f72756d9b4f7b6bd85b1a6764b31312bc375a2298b78b0263d492205d2a5aa7a227abaf41ab4ea8ce0e75728a5177fe90ace36fdc5dba53317bbf90e60a6f2311bb333bf55ba3245f'
C = 'a3bce6e2e677d7855a1a7819eb1879779d1e1eefa21a1a6e205c8b46fdc020a2487fdd07dbae99274204fadda2ba69af73627bdddcb2c403118f507bca03cb0bad7a8cd03f70defc31fa904d71230aab98a10e155bf207da1b1cac1503f48cab3758024cc6e62afe99767e9e4c151b75f60d8f7989c152fdf4ff4b95ceed9a7065f38c68dee4dd0da503650d3246d463f504b36e1d6fafabb35d2390ecf0419b2bb67c4c647fb38511b34eb494d9289c872203fa70f4084d2fa2367a63a8881b74cc38730ad7584328de6a7d92e4ca18098a15119baee91237cea24975bdfc19bdbce7c1559899a88125935584cd37c8dd31f3f2b4517eefae84e7e588344fa5'
n = int(N,16)
e = int(E,16)
c = int(C,16)


d = owiener.attack(e, n)

if d is None:
   print("Failed")
else:
  print('d = ' , d)
#d =  4405001203086303853525638270840706181413309101774712363141310824943602913458674670435988275467396881342752245170076677567586495166847569659096584522419007


print(long_to_bytes(pow(c,d,n)))
```

### 6. Common modulus

#### 1.External attack

Cuộc tấn công mô đun phổ biến lợi dụng thực tế là nếu hai khóa công khai RSA chia sẻ cùng một mô đun (n), các bản mã được mã hóa bằng các khóa này cũng sẽ chia sẻ cùng một mô đun. Giả sử chúng ta có hai bản mã, C1 và C2, được mã hóa bằng các khóa công khai tương ứng (e1, n) và (e2, n).

$$C_1 = M^{e1} (mod(N))$$

$$C_2 = M^{e_2} (mod(N))$$


Để thực hiện tấn công tìm m thì ta cần tìm u, v từ

$$GCD(e_1, e_2) = 1 <=> e1 * u + e_2 * v = 1$$


$$C_1 = M^{e_1}$$

$$C_2 = M^{e_2}$$

$$C_1^u = M^{e_1} . u$$

$$C_2^v = M^{e_2} . v$$


$$C_1^u * C_2^v = M^{e_1} . u  .  M^{e_2} . v = M^{e_1 . u + e_2 . v} = M$$


Từ đó ta sẽ khôi phục được bản mã.


```python
# RSA5 byuctf 2023

from Crypto.Util.number import  * 
from numpy import  * 
n = 158307578375429142391814474806884486236362186916188452580137711655290101749246194796158132723192108831610021920979976831387798531310286521988621973910776725756124498277292094830880179737057636826926718870947402385998304759357604096043571760391265436342427330673679572532727716853811470803394787706010603830747
e1 = 65537

c1 = 147465654815005020063943150787541676244006907179548061733683379407115931956604160894199596187128857070739585522099795520030109295201146791378167977530770154086872347421667566213107792455663772279848013855378166127142983660396920011133029349489200452580907847840266595584254579298524777000061248118561875608240

e2 = 65521

c2 = 142713643080475406732653557020038566547302005567266455940547551173573770529850069157484999432568532977025654715928532390305041525635025949965799289602536953914794718670859158768092964083443092374251987427058692219234329521939404919423432910655508395090232621076454399975588453154238832799760275047924852124717

def egcd(a,b):
    u, u1 = 1, 0
    v, v1 = 0, 1
    while b:
        q = a // b
        u, u1 = u1, u - q  *  u1
        v, v1 = v1, v - q  *  v1
        a, b = b, a - q  *  b
    return u, v, a

print(egcd(e1, e2))

u=-4095 
v=4096


c1_inv = inverse(c1, n)
m= (pow(c1_inv,-u)  *  pow(c2,v))%n
print(long_to_bytes(m))
```

#### 2.internal attacker

Giả định rằng bạn là một phần của nhóm và sở hữu khóa công khai và riêng tư với cùng mô đun với những người khác.

Ta có:

$$e * d = 1 mod \phi(n)$$
    
$$e * d = k  *  \phi(n) + 1$$
    
$$k = \frac{e * d - 1}{\phi(n)}$$
    
$$φ(n) = \frac{e * d - 1}{k}$$


Nếu kết quả không phải là số nguyên, hãy tăng k dần cho đến khi thu được kết quả.

Bây giờ bạn đã biết φ(n) và e của nạn nhân, bạn có thể tính toán các khóa $d(victim) = e(victim) ^ {-1} \ mod \ φ(n)$ riêng tương ứng và giải mã các tin nhắn

### 7.Blinding Attack

Khi Marvin cố gắng gửi một tin nhắn tương tự như Alices, Bob nhận thấy rằng tin nhắn có một số thông điệp nguy hiểm trong đó và từ chối ký vào tin nhắn. Nhưng RSA vốn không có bất kỳ cơ chế kiểm tra nào, những ràng buộc này có thể được bỏ qua một cách dễ dàng. Đôi khi chỉ cần nhân thông điệp nguy hiểm với một số nguyên tố là đủ. Vì vậy, Marvin có thể thử một cuộc tấn công mù bằng cách sử dụng các bước sau:

1. Chuẩn bị một bộ đệm $r^e$ (r = số nguyên nhỏ và e = khóa công khai) và gửi tin nhắn nhân với bộ đệm. $M' = ( r^e  *  M ) \ (mod(N))$ . Những bộ đệm này thường được gọi là các yếu tố làm mù.

2. Vì Bob chỉ kiểm tra một số ký tự, chuỗi nhất định, tin nhắn của Marvin sẽ được chấp thuận vì theo quan điểm của Bob, Marvin đang gửi một tin nhắn ngẫu nhiên không chứa bất kỳ văn bản không mong muốn nào. Và bob trả về tin nhắn đã ký. 

$$S’ = (M’)^d \ (mod(N)) = (r^e * M)^d \ (mod(N)) = r^{ed}  *  M^d \ (mod(N)) = r  *  M^d  \ (mod(N))$$

3. Bây giờ tất cả những gì Marvin phải làm là giải mã tin nhắn và loại bỏ yếu tố gây mù. Chữ kí cho thông điệp M chính là : 

$$\frac{S'}{r} = M^d \ (mod(N))$$

### 8. Multi-prime RSA

Với n thông thường chúng ta thường factor ra 2 số nguyên tố nhưng ở trường hợp sau thì n factor ra nhiều số nguyên tố.

$$n = \prod_{i=1}^k p_i$$

$$\phi(n) = \prod_{i=1}^k (p_i - 1)$$

Ở challenge ``Manyprime`` bên dưới thì chúng ta sẽ áp dụng cách tấn công này.


$$n = p_1  *  p_2  *  p_3  *  ...  *  p_n$$

$$\phi(n) = (p_1-1)  *  (p_2-1)  *  (p_3-1)  *  ...  *  (p_n-1)$$


```sage
>>> from Crypto.Util.number import  * 
>>> p1 = 13
>>> p2 = 17
>>> p3 = 89
>>> p4 = 101
>>> n = p1  *  p2  *  p3  *  p4
>>> e = 23
>>> phi = (p1-1)  *  (p2-1)  *  (p3-1)  *  (p4-1)
>>> d = inverse(e,phi)
>>> m = 1337
>>> c = pow(m,e,n)
>>> m == pow(c, d, n)
True
```

### 9. Boneh Durfee Attack

[Boneh Durfee Attack](https://www.sciencedirect.com/science/article/pii/S0304397518305371) là sự mở rộng, nâng cao hơn so với Wiener Attack

Ở đây ``Boneh Durfee`` sẽ tấn công với điều kiện private key lớn hơn: 

$$d < N ^ {0.292}$$

Chúng ta sử dụng tấn công Boneh Durfee để tìm lại d. 

$${E, n} \xrightarrow[d < N^{0.292}]{P} d$$



$$\phi(n) = (p-1)  *  (q-1) = p * q - p - q + 1 = n + 1 - p - q$$
$$e * d = 1  \ \% \ \phi(n)$$
$$e * d = k * \phi(n) + 1$$
$$k * \phi(n) + 1 = 0 \ \% \ e$$
$$k * (n + 1 - p - q) + 1 = 0 \ \% \ e$$
$$2k * [(n + 1) / 2 + (- p - q) / 2] + 1 = 0 \ \% \ e$$
$$f(x, y) = x  * (A + y) + 1$$
```

Khi đó ta dựng lattices từ ``f(x,y) = x  * (A + y) + 1 ``

Việc còn lại private key d được tìm kiếm với việc giải ra x, y.

Sau đây là ví dụ áp dụng ``boneh durfee`` trong bài ``Everything is Still Big``

Ở đây matrix của nó rất to nên ta không thể lập bằng tay trên sage được

```python
import itertools
from sage.all import  * 

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i)  *  f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base  *  prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial( * bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()
	B = B.change_ring(QQ); print(len(B.rows()), len(B.columns()));
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B * monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []


def boneh_durfee(N, e):
	print('Boneh Durfee')
	bounds = (floor(N^.25), 2^1024)
	d = random_prime(bounds[0])
	e = e
	R = Integers(e)
	P.<k, s> = PolynomialRing(R)
	f = 2 * k * ((N+1)//2 - s) + 1
	print(small_roots(f, bounds, m=3, d=4))


if __name__ == '__main__':
	print('Generating primes')
	e = 19822480419274488251677307922322581373608204916680174673515561360377028968995622607105335755414698144839412875613842080380230300482081946559177683666445909117111224336011873134132068056373656982714080443846061013910593976113415924274483397122945817679487981728613001314822288629582438110592231444108617950478126633605615041008363059448762655342571466013321463018102191788621452554997775676351436919999398565010668785252540431172512816473968178117862553874600835604298639910296325807391721223375419556418763943323750839521188471388175040976788107840583526861438993050030109324607729519719906931135902316161956554417247
	N = 22363547196442286210426096667664934311317202577331708826153312267732060185205433048808318440463775968421571822227366261954714323978290561533582199565520788429312336490136251056698920021717041035283985925620392112442824974178172021230849595039039306862922738621825885516779477934926848831948958100398352376077348421245571051324795910162119087349950756020138069248337386146521430971157062177977730152042384068692748838755054309828353321199177441035894790043246481449883627784291325743830605685598965856794606303061786664661856150516456672469573269821203622123914965529899157206838756880892870142776988576626372988177707
	print(f"{N = }")
	print(f"{e = }")

	boneh_durfee(N, e)
```

### 10. Bleichenbacher’s Attack
 
|00|02|Padding|00|Data block|
|:--|:--|:--|:--|:--|


Cuộc tấn công này có thể áp dụng khi trao đổi khóa diễn ra bằng thuật toán RSA và phần đệm được sử dụng là PKCS # 1 v1.5.

Cách thức hoạt động của Attack:

1. Lưu ý rằng trong quá trình thiết lập phiên TLS với trao đổi khóa RSA, máy khách chọn một số 48 bit ngẫu nhiên (2 byte phiên bản giao thức và 46 byte ngẫu nhiên), pad theo sơ đồ mã hóa PKCS để tạo cùng thứ tự modulo n. Toàn bộ sự việc sau đó được nâng lên số mũ công khai e modulo n. Về phía người nhận, sau khi giải mã, dữ liệu được xác minh để căn chỉnh đúng nếu không gói sẽ bị loại bỏ. Sau khi giải mã, người nhận kiểm tra xem dữ liệu văn bản thuần túy có bắt đầu bằng ``0x00 02 ``, nếu không nó bị loại bỏ, thì tất cả các byte sẽ bị bỏ qua cho đến khi tìm thấy 0x00.

2. dữ liệu đệm PKCS phải luôn bắt đầu bằng 0x00 0x02.

Giả sử kẻ tấn công nhận được văn bản mật mã C về cơ bản là $$M = c^d (modN)$$ kẻ tấn công không biết về M (được đệm PKCS) nhưng anh ta biết về khóa công khai (e, n).

$$C = M^e(mod(N))$$

Kẻ tấn công sau đó nhân giá trị mật mã này với một s đã chọn. Đối với tất cả các trường hợp lỗi, máy chủ sẽ báo lỗi. Kẻ tấn công tiếp tục thay đổi giá trị của s và đợi cho đến khi được máy chủ chấp nhận.

$$C' = Cs^e (mod(N))$$

Khi máy chủ chấp nhận C 'có nghĩa là C'sau khi giải mã bắt đầu bằng 0x00 0x02 và C' là mã hóa hợp lệ cho M  *  s với đệm PKCS.

$$M' = (Cs^e)^d (mod(N)) = C^d s^{ed} (mod(N)) = ms (mod(N)) $$

Chọn hằng số $$B = 2^8(k−2)$$ k là kích thước khóa tính bằng byte, giống như trong RSA chúng ta nói 2048 bit (256 byte).

Vì 2 byte đầu tiên là 0x00 0x02 ,2⁸ được thực hiện để hiển thị thông điệp trong biểu diễn bit

Khi tin nhắn được máy chủ chấp nhận, điều đó có nghĩa là.

$$2B < m * s (mod(N)) < 3B$$

Nếu thông điệp được chấp nhận, 2 byte đầu tiên được ``0x00 02`` và do đó thông điệp $$m * s \ \% \ N $$ hoàn toàn nhỏ hơn khi 2 byte đầu tiên được 0x00 03. Và giống như kẻ tấn công tiếp tục giảm ranh giới bằng cách thực hiện tìm kiếm nhị phân cho đến khi một giá trị duy nhất được tìm thấy.

### 11. Brute force attack on small secret CRT-Exponents

Giả sử tôi có:

$$d_p ≡ e^{-1} \ (mod(p-1))$$

$$d_q ≡ e^{-1} \ (mod(q-1))$$

Với dp ta có:
    
$$d_p  *  e ≡ 1 \ (mod(p-1))$$
    
$$d_p  *  e ≡ 1 + k(p-1)$$

Chọn một số m bất kì sao cho ``GCD(m, p) = 1``

Khi đó:

$$m^{d_p * e} = m^{1+k(p-1)} = m  *  m^{(p-1)^k}  $$

Theo Fermat’s little theorem ta có:

$$m  *  m^{(p-1)^k}(modP) = m  *  1^k(modP) = m (modP) $$

$$m^{e * d_p} ≡ m(modP) \ hay \ m - m^{e * d_p} = k * p$$

Và cuối cùng:


$$GCD(m - m^{e .d_p}, n) = GCD(k.p, p . q) = p$$ 

với ``m < n ``


```sage
sage: from Crypto.Util.number import isPrime, GCD
....:
....:n=95580702933509662811256129990158655210667121276245053843875590334281563078868202152845967187641817281520364662600110239110410372520340630639373679599982371620736610194814723749147422221945978800055101110346161945811520158431287139909125886966214800526831490560384144156085296004816333892025839072729987354233
.... e=1817084480271067137841898198122075168542117135135738925285694555698012943264936112861815937200507849960517390660821911331068907250788900674614345400567411
....: m = 7516789928765 # random number
....: for dp in range(1000000):
....:     f = GCD(m-pow(m, e * dp, n), n)
....:     if f > 1:
....:         print(dp, f)
....:         break
....: p = f
....: q = n // p
....: print(isPrime(p))
....: print(isPrime(q))
....:

187261 8275629468590614667884614599278593237258686111405345888268221129814081809682982742676180514534238891248302334619164139839173447495925780801832743975865311
True
```


## Reference

[1] https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-1/ (part-2, part-3, part-4)

[2] https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf

[3] https://en.wikipedia.org/wiki/RSA_(cryptosystem)

[4] https://en.wikipedia.org/wiki/Chinese_remainder_theorem#:~:text=In%20mathematics%2C%20the%20Chinese%20remainder,are%20pairwise%20coprime%20(no%20two)

[5] https://github.com/defund/coppersmith/tree/master

[6] https://cr.yp.to/bib/2001/coppersmith.pdf
