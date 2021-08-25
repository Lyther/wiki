# secret_share

Category: Cryptography

Source: 祥云杯2021

Author: unknown

Score: 35

## Description

Here is running a secret sharing system. But if the server colludes with some clever users, the whole system will not be safe any more.`nc 0.cloud.chals.io 19892`

[ secret_share.zip](https://compass.ctfd.io/files/c8c0d798ef6366434e1c311a8e92922a/secret_share.zip?token=eyJ1c2VyX2lkIjoxLCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjoxMDF9.YSXzgQ.iRlmoJ_vuyjWoE_H7vZjM2iTKhQ)

## 题目描述

*测试了一下，发现要用python 2运行服务端代码。*

题目基于离散对数，也就是![[公式]](https://www.zhihu.com/equation?tex=y%3Dg%5Ex)，生成元![[公式]](https://www.zhihu.com/equation?tex=g)和模素数![[公式]](https://www.zhihu.com/equation?tex=p)在代码中给出。

题目的加密如下：产生随机的![[公式]](https://www.zhihu.com/equation?tex=e%2C+v)，计算

![[公式]](https://www.zhihu.com/equation?tex=E+%3D+g%5Ee%2C+V%3Dg%5Ev)

![[公式]](https://www.zhihu.com/equation?tex=s%3Dv%2BeH%28E%7C%7CV%29)

![[公式]](https://www.zhihu.com/equation?tex=c%3Dm+y%5E%7Be%2Bv%7D)

产生的密文为![[公式]](https://www.zhihu.com/equation?tex=%5Cleft%28c%2C+%28E%2C+V%2C+s%29%5Cright%29)。

并且题目还有一个二次加密：

![[公式]](https://www.zhihu.com/equation?tex=E%27+%3D+E%5E%7Br%7D%2C+V%27%3DV%5E%7Br%7D)

![[公式]](https://www.zhihu.com/equation?tex=s%27%3Ds+r)

产生的密文为![[公式]](https://www.zhihu.com/equation?tex=%5Cleft%28c%2C+%28E%27%2C+V%27%2C+s%27%29%5Cright%29)

一开始oracle给出一对![[公式]](https://www.zhihu.com/equation?tex=%28x%2C+y%29)，但是我们对flag加密所用的为![[公式]](https://www.zhihu.com/equation?tex=%28x_f%2C+y_f%29)。我们能知道flag对应密文![[公式]](https://www.zhihu.com/equation?tex=%5Cleft%28c_f%2C+%28E_f%2C+V_f%2C+s_f%29%5Cright%29)。可以得到更多提示，但是我们需要过如下挑战：

oracle每次生成一个200位的![[公式]](https://www.zhihu.com/equation?tex=m)，然后进行一个`rk_gen`

`rk_gen`是一个多项式生成，一开始生成一个![[公式]](https://www.zhihu.com/equation?tex=x%27%2C+r%27)，记![[公式]](https://www.zhihu.com/equation?tex=Y_0+%3D+y%5E%7Bx%27+x_f%7D)，![[公式]](https://www.zhihu.com/equation?tex=Y_i+%3D+y_i%5E%7Bx%27+x_f%7D)对![[公式]](https://www.zhihu.com/equation?tex=i+%5Cge+1)。

这里会给出一个![[公式]](https://www.zhihu.com/equation?tex=X_0+%3D+g%5E%7Bx%27+x_f%7D)的值让我们知道。

对`encoder`观察得：

一开始是![[公式]](https://www.zhihu.com/equation?tex=%5B1%2C+-Y_0%5D)

第一回就变成了![[公式]](https://www.zhihu.com/equation?tex=%5B1%2C+-Y_0-Y_1%2C+Y_0Y_1%5D)

第二回就变成了![[公式]](https://www.zhihu.com/equation?tex=%5B1%2C+-Y_0-Y_1-Y_2%2C+Y_0Y_1%2BY_0Y_2%2BY_1Y_2%2C+-Y_0Y_1Y_2%5D)

观察与归纳发现之后也满足这样的形式。

由韦达定理，上面的也就可以看成是多项式![[公式]](https://www.zhihu.com/equation?tex=f%28x%29+%3D+%28x-Y_0%29%28x-Y_1%29%28x-Y_2%29)的展开式之系数。

并且实际给我们的时候，我们知道的是

![[公式]](https://www.zhihu.com/equation?tex=g%28x%29+%3D+f%28x%29%2Br%27+%3D+%28x-Y_0%29%28x-Y_1%29%28x-Y_2%29%5Cldots+%2B+r%27)

然后

![[公式]](https://www.zhihu.com/equation?tex=d%3DH%28X_0%7C%7Cr%27%29)

![[公式]](https://www.zhihu.com/equation?tex=r%3Dx_f+d)

并且把![[公式]](https://www.zhihu.com/equation?tex=m)用![[公式]](https://www.zhihu.com/equation?tex=y_f)加密后，再利用这里算出来的![[公式]](https://www.zhihu.com/equation?tex=r)进行二次加密之后的结果![[公式]](https://www.zhihu.com/equation?tex=%5Cleft%28c%2C+%28E%27%2C+V%27%2C+s%27%29%5Cright%29)告诉我们。需要我们给出![[公式]](https://www.zhihu.com/equation?tex=m)的值。

如果4次挑战成功，那么oracle提示我们这4次所产生![[公式]](https://www.zhihu.com/equation?tex=r)的值之积。

## 我的解答

首先我们来看这个密码系统的解密：假设我们有![[公式]](https://www.zhihu.com/equation?tex=x)的话，密文可以被写成

![[公式]](https://www.zhihu.com/equation?tex=c%3Dm+y%5E%7Be%2Bv%7D%3Dm%28g%5Ex%29%5E%7Be%2Bv%7D%3Dm%28g%5E%7Be%2Bv%7D%29%5Ex%3Dm%28EV%29%5Ex)

所以

![[公式]](https://www.zhihu.com/equation?tex=m%3Dc%28EV%29%5E%7B-x%7D)

这样我们就可以解得明文![[公式]](https://www.zhihu.com/equation?tex=m)。

接下来我们看挑战。实际上，挑战外部只有![[公式]](https://www.zhihu.com/equation?tex=x_f)和![[公式]](https://www.zhihu.com/equation?tex=y)参与了运算。我们的目的是求出挑战中的![[公式]](https://www.zhihu.com/equation?tex=m)。

先对二次加密的结果进行分析：

![[公式]](https://www.zhihu.com/equation?tex=c%3Dm+y_f%5E%7Be%2Bv%7D)

![[公式]](https://www.zhihu.com/equation?tex=E%27+%3D+E%5E%7Br%7D+%3D+g%5E%7Ber%7D+%3D+g%5E%7Be+x_f+d%7D+%3D+y_f%5E%7Bed%7D)

![[公式]](https://www.zhihu.com/equation?tex=V%27%3DV%5E%7Br%7D+%3D+g%5E%7Bv+x_f+d%7D%3Dy_f%5E%7Bvd%7D)

![[公式]](https://www.zhihu.com/equation?tex=s%27%3Ds+r+%3D+%28v%2BeH%28E%7C%7CV%29%29r)

那么，如果我们已知![[公式]](https://www.zhihu.com/equation?tex=d)的话，我们就可以通过模![[公式]](https://www.zhihu.com/equation?tex=p)的阶为![[公式]](https://www.zhihu.com/equation?tex=p-1)这一性质，求出![[公式]](https://www.zhihu.com/equation?tex=y_f%5Ee)和![[公式]](https://www.zhihu.com/equation?tex=y_f%5Ev)，进而根据上面密码系统的解密步骤解出明文![[公式]](https://www.zhihu.com/equation?tex=m)，完成挑战。

又![[公式]](https://www.zhihu.com/equation?tex=d%3DH%28X_0%7C%7Cr%27%29)，这里我们![[公式]](https://www.zhihu.com/equation?tex=X_0+%3D+g%5E%7Bx%27+x_f%7D)是知道的，所以我们只需要求![[公式]](https://www.zhihu.com/equation?tex=r%27)的值。

事实上，

![[公式]](https://www.zhihu.com/equation?tex=Y_0+%3D+y%5E%7Bx%27+x_f%7D+%3D+%28g%5Ex%29%5E%7Bx%27+x_f%7D+%3D+%28g%5E%7Bx%27+x_f%7D%29%5Ex+%3D+X_0%5Ex)

也就是说![[公式]](https://www.zhihu.com/equation?tex=Y_0)我们也是已知的。那么相当于说我们就可以有一个多项式![[公式]](https://www.zhihu.com/equation?tex=h%28x%29%3Dx-Y_0)。

那么![[公式]](https://www.zhihu.com/equation?tex=g%28x%29)模![[公式]](https://www.zhihu.com/equation?tex=h%28x%29)的值就是![[公式]](https://www.zhihu.com/equation?tex=r%27)！

到这里，挑战解决：首先我们可以算出![[公式]](https://www.zhihu.com/equation?tex=r%27)，进而算出![[公式]](https://www.zhihu.com/equation?tex=d)并解密出![[公式]](https://www.zhihu.com/equation?tex=m)，完成挑战。

而挑战送我们的奖励也就是四个

![[公式]](https://www.zhihu.com/equation?tex=r%3Dx_f+d)

的乘积，而这里![[公式]](https://www.zhihu.com/equation?tex=x_f)是不变的，所以我们可以算出![[公式]](https://www.zhihu.com/equation?tex=x_f%5E4)，然后模![[公式]](https://www.zhihu.com/equation?tex=p)意义下解方程得到![[公式]](https://www.zhihu.com/equation?tex=x_f)，进而对flag对应密文![[公式]](https://www.zhihu.com/equation?tex=%5Cleft%28c_f%2C+%28E_f%2C+V_f%2C+s_f%29%5Cright%29)进行解密即可。

搞到提示的代码如下：

```python
# sage -python gao_2.py
from pwn import *
from sage.all import *
from Crypto.Util.number import *
from hashlib import sha256

def h2(m):
    return int(sha256(m).hexdigest(), 16)

p = 0xb5655f7c97e8007baaf31716c305cf5950a935d239891c81e671c39b7b5b2544b0198a39fd13fa83830f93afb558321680713d4f6e6d7201d27256567b8f70c3
g = 0x85fd9ae42b57e515b7849b232fcd9575c18131235104d451eeceb991436b646d374086ca751846fdfec1ff7d4e1b9d6812355093a8227742a30361401ccc5577

conn = remote('47.104.85.225', 62351)
conn.sendlineafter('choice>', '1')
conn.recvuntil('Please take good care of it!\n')
s = conn.recvline()
y, x = eval(s)

conn.sendlineafter('choice>', '2')
nlist = [33, 65, 129, 257]

for n in nlist:
    # n = 33 # 33
    conn.recvuntil('The cipher shared to you\n')
    s = conn.recvline()
    c, (EE, VV, sr) = eval(s)
    conn.recvuntil('prefix, encoder = ')
    s = conn.recvline()
    encoder, prefix_hex = eval(s)
    prefix = int(prefix_hex, 16)
    Y0 = pow(prefix, x, p)

    P, (xx, ) = PolynomialRing(Zmod(p), 'xx').objgens()
    f1 = xx ** n
    for i in range(n):
        f1 += xx ** (n-i-1) * encoder[i]

    f2 = xx - Y0
    ff = f1 % f2
    r = int(ff)
    d = h2(prefix_hex.decode('hex') + long_to_bytes(r).rjust(64, '\x00')) | 1
    print(d)

    d2 = inverse(d, p-1)
    yev = pow(EE * VV, d2, p)
    m = c * inverse(yev, p) % p
    conn.sendline(hex(m)[2:])

conn.interactive()
```

然后得到提示和密文。解密的脚本如下：

```python
from Crypto.Util.number import *

p = 0xb5655f7c97e8007baaf31716c305cf5950a935d239891c81e671c39b7b5b2544b0198a39fd13fa83830f93afb558321680713d4f6e6d7201d27256567b8f70c3
g = 0x85fd9ae42b57e515b7849b232fcd9575c18131235104d451eeceb991436b646d374086ca751846fdfec1ff7d4e1b9d6812355093a8227742a30361401ccc5577

c, (E, V, s) = (5585968041074025086153882651703151644252825797961750029846368850560274818374166788547796736374559756281986206108084144666719010198655069698311903223194165L, (7907022716121671499111670222633646508450620325985407809966619468858884394742418166662560533967841329320157194633470489479583638083109335158547004325407745L, 8405942693799264870593925170154538171389476686350775031149946204774020645560022720688012855017145834685204712310735071692308136544637274001444374071172215L, 4472917796572038030768951841580005906571419088430724545004411546215611452075638469061832923050311132351135006369648270174176244462571628294865215006848977L))

dlist = [88705054545798462592463535140496546230654103298029754196033655251576954884967,
3171548216431031323271233816116991780227219532639047192797048831559660952785,
115398379312678080372309706872824527861787247942202400632537054143103194010615,
85791902547465660732182842994118602329957914363880964530800626818535559558315]

rs = 0x17be2ea8187855e3a4ff52657728c70efa4d8d51a9afb3a59fceb1ef85b377613f0271008951a7fcdf741a97892ec4a61c724e49ddb7d46b0e735448d35a1f29L

Zp = Zmod(p)

d = Zp(1)
for x in dlist:
    d *= x

rs = Zp(rs)
s = rs * d ^ -1

P.<x> = PolynomialRing(Zp)
f = x^4 - s
fr = f.roots()

c, E, V = map(Zp, (c, E, V))

for x1, po in fr:
    x1 = int(x1)
    yev = (E * V) ^ x1
    m = c * yev ^ -1
    m = int(m)
    print(long_to_bytes(int(m)).encode('hex'))
```

## Flag

```text
flag{504d0411-6707-469b-be31-9868200aca95}
```

## Reference

Writeup from [https://zhuanlan.zhihu.com/p/402690414](https://zhuanlan.zhihu.com/p/402690414)

