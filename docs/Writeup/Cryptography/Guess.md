# Guess

Category: Cryptography

Source: 祥云杯2021

Author: unknown

Score: 15

## Description

在一次任务中我遇到了一个challenge，我的队友给我发了一个他截获的hint，你利用这个hint能帮我完成这个challenge吗？`nc 0.cloud.chals.io 14337`

[ guess.zip](https://compass.ctfd.io/files/e0221f22e34813e523e1fed49c8dcf7f/guess.zip?token=eyJ1c2VyX2lkIjoxLCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjoxMDB9.YSXy0A.23iDNJbW3VvcaascdXS4CDvImAY)

## 题目描述

首先它有一个密钥生成的代码。`key`是一个20*4的矩阵，元素均为三位数，然后右乘一个随机1024位矩阵![[公式]](https://www.zhihu.com/equation?tex=M)得到![[公式]](https://www.zhihu.com/equation?tex=H)。我们只知道`key`矩阵第一行的内容，以及![[公式]](https://www.zhihu.com/equation?tex=H)的值，但是不知道![[公式]](https://www.zhihu.com/equation?tex=M)矩阵的内容。

猜测可能可以用格基规约先弄出`key`，但是有感觉不靠谱，我们先放一放，审计一下oracle交互的`Guess.py`文件。

文件中使用的密码算法是Paillier算法，该算法支持同态加法。oracle交互逻辑如下：

1. 给出算法的加密密钥（即公钥）。
2. 给出一个密文，oracle返回明文。
3. 给出两个明文![[公式]](https://www.zhihu.com/equation?tex=m_1%2C+m_2), oracle返回![[公式]](https://www.zhihu.com/equation?tex=%5Cmathrm%7BEnc%7D%28m_1+m_2+k_R%29)或者![[公式]](https://www.zhihu.com/equation?tex=%5Cmathrm%7BEnc%7D%28m_1+m_2+k_%7BR%2B1%7D%29)的其中一项，其中![[公式]](https://www.zhihu.com/equation?tex=R%3D2t%2C+0+%5Cle+t+%3C+40)是一随机的偶数，![[公式]](https://www.zhihu.com/equation?tex=k)是那80个100-1000的数构成的一个列表。
4. 给出一个不能和第3步解密结果相同的密文，oracle返回明文。
5. 判断第3步中oracle返回了哪个密文，并告诉oracle结果以检验。如果oracle检验成功，则进行下一轮；如果oracle检验失败，则终止连接。 需要检验成功32轮才能拿到flag。

## 我的解答

本质上只需要把`key`恢复出来即可。但是我们可以在上面的第四步做文章。

第四步可以用Paillier算法的性质来构造密文。记![[公式]](https://www.zhihu.com/equation?tex=g%3Dn%2B1)，Paillier算法对于一个明文![[公式]](https://www.zhihu.com/equation?tex=m)，先随机生成一个![[公式]](https://www.zhihu.com/equation?tex=r)，然后计算![[公式]](https://www.zhihu.com/equation?tex=c%3Dg%5Em+r%5En+%5Cbmod+n%5E2)。

那么，如果我们已经知道两个明文密文对![[公式]](https://www.zhihu.com/equation?tex=%28m%27_1%2C+c%27_1%29%2C+%28m%27_2%2C+c%27_2%29)，我们计算

![[公式]](https://www.zhihu.com/equation?tex=c%27+%5Cequiv+c%27_1+c%27_2+%5Cequiv+%5C+g%5E%7Bm%27_1%2Bm%27_2%7D%28r%27_1+r%27_2%29%5E%7Bn%7D%28%5Cbmod+n%5E2%29)

此时我们会发现这个新构造的密文![[公式]](https://www.zhihu.com/equation?tex=c%27)对应明文![[公式]](https://www.zhihu.com/equation?tex=m%27+%3D+m%27_1+%2B+m%27_2)。

因此，我们可以令![[公式]](https://www.zhihu.com/equation?tex=c_1%27)为oracle所给的密文，并使用题目所给的公钥得到另一个明文密文对![[公式]](https://www.zhihu.com/equation?tex=%28m_2%27%2C+c_2%27%29)，譬如令![[公式]](https://www.zhihu.com/equation?tex=m%27_2%3D2)，然后用![[公式]](https://www.zhihu.com/equation?tex=n)和![[公式]](https://www.zhihu.com/equation?tex=g)加密得到![[公式]](https://www.zhihu.com/equation?tex=c_2%27)，并构造密文

![[公式]](https://www.zhihu.com/equation?tex=c%27+%3D+c%27_1+c%27_2+%5Cbmod+n%5E2)

然后就可以在oracle的第四步输入这个![[公式]](https://www.zhihu.com/equation?tex=c%27)，这样oracle所解出的明文![[公式]](https://www.zhihu.com/equation?tex=m%27)就是

![[公式]](https://www.zhihu.com/equation?tex=m_1+m_2+k_%7BR%2Bs%7D%2B2)

因为题目所给的`key`是固定的，也就是说![[公式]](https://www.zhihu.com/equation?tex=k)是固定的，所以oracle解出的明文![[公式]](https://www.zhihu.com/equation?tex=m%27)也是有限的（80个），这就变成了一个80个样本的二分类问题。我们可以把所输入的![[公式]](https://www.zhihu.com/equation?tex=m_1)和![[公式]](https://www.zhihu.com/equation?tex=m_2)固定，可以多次和oracle交互，先尝试猜测答案，根据oracle的检验结果得到若干![[公式]](https://www.zhihu.com/equation?tex=m%27+%5Cto+s)的先验知识。

然后只要先验知识足够多，那就能保证很大概率猜对。猜测答案代码如下：

```python
from hashlib import sha256
import string
import itertools
from pwn import *
from Crypto.Util.number import *
import random

def enc(n, g, m):
    while 1:
        r = random.randint(2, n - 1)
        if GCD(r, n) == 1:
            break
    c = (pow(g, m, n ** 2) * pow(r, n, n ** 2)) % (n ** 2)
    return c

with open('gao_log_3', 'a') as f:
    while (True):
        conn = remote('47.104.85.225', 57811)

        # SHA-256(?+hUWmo9BJ34LI) == 3919fa0f116d1a87c97d98dd43e08f77b090df5c88b1417c1c7e2c006a200aef
        s = conn.recvline().strip().decode()
        s2 = s[10:22]
        ans = s[-64:]

        for i in itertools.product(string.ascii_letters + string.digits, repeat=4):
            s1 = ''.join(i)
            ss = s1 + s2
            if (sha256(ss.encode()).hexdigest() == ans):
                conn.sendline(s1)
                break
        
        while (True):
            conn.recvuntil('n = ')
            n = conn.recvline()
            n = int(n)

            conn.recvuntil('g = ')
            g = conn.recvline()
            g = int(g)

            conn.sendlineafter('Please give me one decimal ciphertext.', '2')
            conn.recvuntil('This is the corresponding plaintext.\n')
            mm = conn.recvline()
            mm = int(mm)

            conn.sendlineafter('Give me m0.', '40343')
            conn.sendlineafter('Give me m1.', '52051')
            conn.recvuntil('This is a ciphertext.\n')
            c = conn.recvline()
            c = int(c)

            mm = 2
            c2 = enc(n, g, mm)
            cc = (c * c2) % (n ** 2)
            conn.sendlineafter('Please give me one decimal ciphertext', str(cc))
            conn.recvuntil('This is the corresponding plaintext.\n')
            m2 = conn.recvline()
            m2 = int(m2)

            conn.sendlineafter('m1 -> c1)?', '0')
            s = conn.recvuntil('!')
            if (b'Sorry') in s:
                f.write(f'{m2}, 1\n')
                conn.close()
                break
            else:
                f.write(f'{m2}, 0\n')
```

利用猜测答案所得的知识库进行交互的代码如下：

```python
from hashlib import sha256
import string
import itertools
import random
from pwn import *
from Crypto.Util.number import *

def enc(n, g, m):
    while 1:
        r = random.randint(2, n - 1)
        if GCD(r, n) == 1:
            break
    c = (pow(g, m, n ** 2) * pow(r, n, n ** 2)) % (n ** 2)
    return c

m2ans = {}
cnt = 0
for i in range(1, 5):
    with open(f'gao_log_{i}', 'r') as f:
        s = f.read()


    for sline in s.splitlines():
        m, ans = map(int, sline.split(','))
        m2ans[m] = ans
        cnt += 1

print(len(m2ans))
conn = remote('47.104.85.225', 57811)
# SHA-256(?+hUWmo9BJ34LI) == 3919fa0f116d1a87c97d98dd43e08f77b090df5c88b1417c1c7e2c006a200aef
s = conn.recvline().strip().decode()
s2 = s[10:22]
ans = s[-64:]

for i in itertools.product(string.ascii_letters + string.digits, repeat=4):
    s1 = ''.join(i)
    ss = s1 + s2
    if (sha256(ss.encode()).hexdigest() == ans):
        conn.sendline(s1)
        break
for i in range(32):
    conn.recvuntil('n = ')
    n = conn.recvline()
    n = int(n)

    conn.recvuntil('g = ')
    g = conn.recvline()
    g = int(g)

    conn.sendlineafter('Please give me one decimal ciphertext.', '2')
    conn.recvuntil('This is the corresponding plaintext.\n')
    mm = conn.recvline()
    mm = int(mm)

    conn.sendlineafter('Give me m0.', '40343')
    conn.sendlineafter('Give me m1.', '52051')
    conn.recvuntil('This is a ciphertext.\n')
    c = conn.recvline()
    c = int(c)

    mm = 2
    c2 = enc(n, g, mm)
    cc = (c * c2) % (n ** 2)
    conn.sendlineafter('Please give me one decimal ciphertext', str(cc))
    conn.recvuntil('This is the corresponding plaintext.\n')
    m2 = conn.recvline()
    m2 = int(m2)
    if (m2 in m2ans):
        print('Find')
        conn.sendlineafter('m1 -> c1)?', str(m2ans[m2]))
    else:
        print('Guess')
        conn.sendlineafter('m1 -> c1)?', '0')
    s = conn.recvuntil('!')
    if (b'Sorry') in s:
        print(f'GG {i}')
        conn.close()
        break

conn.interactive()
```

## Flag

```text
flag{e87fdfb6-8007-4e1c-861f-5bde3c8badb3}
```

## Reference

Writeup from [https://zhuanlan.zhihu.com/p/402690414](https://zhuanlan.zhihu.com/p/402690414)

