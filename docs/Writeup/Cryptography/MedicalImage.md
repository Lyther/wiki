# MedicalImage

Category: Cryptography

Source: 巅峰极客赛 2021

Author: unknown

Score: 25

## Solution

一个图片加密脚本, 函数`f(x)`被隐藏了, 但给了提示, 是`logistic map`, (在b站看下视频, 数学真的好神奇啊).而且参数rr是最大合法值, 也就是44, 那么函数`f(x)`为

f(x)=4x(1−x)f(x)=4x(1−x)

然后就是对着加密流程写解密了…. 没有啥特别的 逆着加密过程写解密就行, p0,c0就那几个值爆破就行, 一开始随便拿101,201试了下…直接对了

```
from decimal import *
from PIL import Image
import numpy as np
from time import time
getcontext().prec = 20


R = Decimal(4)
r1 = Decimal('0.478706063089473894123')
r2 = Decimal('0.613494245341234672318')
r3 = Decimal('0.946365754637812381837')
const = 10 ** 14
im = Image.open(
    r'flag_enc.bmp'
)
size = im.size
w,h = size
im = np.array(im)



def f(x):
    return Decimal(4 * x * (1 - x))

for i in range(200):
    r1 = f(r1)
    r2 = f(r2)
    r3 = f(r3)

S = time()
p0 = 101
c0 = 201
for x in range(w):
    for y in range(h):
        k = int(round(const*r3))%256
        k = bin(k)[2:].ljust(8,'0')
        k = int(k[p0%8:]+k[:p0%8],2)
        r3 = f(r3)
        m0 = ((k ^ im[y,x] ^ c0 ) - k) % 256
        c0 = im[y,x]
        p0 = m0
        im[y,x] = m0
arr = []
for x in range(w):
    for y in range(h):
        x1 = int(round(const*r1))%w
        y1 = int(round(const*r2))%h
        arr += [(x,y,x1,y1)]
        r1 = f(r1)
        r2 = f(r2)
for z in arr[::-1]:
    x,y,x1,y1 = z
    tmp = im[y,x]
    im[y,x] = im[y1,x1]
    im[y1,x1] = tmp  
m = Image.new('P', size,'white')
pixels = m.load()
for i in range(m.size[0]):
    for j in range(m.size[1]):
        pixels[i,j] = (int(im[j][i]))
m.save(r'flag.bmp')
print(time()-S)
```