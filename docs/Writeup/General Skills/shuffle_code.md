# shuffle_code

Category: General Skills

Source: 祥云杯2021

Author: unknown

Score: 45

## Description

[_shuffle_code.zip](https://compass.ctfd.io/files/8d360d8246c56a97349d626b654efa7c/shuffle_code.zip?token=eyJ1c2VyX2lkIjoxLCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjoxMDZ9.YSX1Vg.oDvsPieFHNto3YC2DMKNau7RyrA)

## 题目描述

题目附件给出来的拖入010 editor查看，发现是个倒着的PNG。将其倒回来，打开发现是一个二维码

![img](https://pic3.zhimg.com/80/v2-79da176dbbcee490264bc4aec94bfcbe_720w.jpg)开局一个码

## 我的解答

二维码扫码得：

```text
col426327/1132122/1211132223/3113253/61531113/111312/5323125/2222/11122153/311111/14312121/11231211/2423211/262121/422221/622132/31121/221122111/5122311/2111221221/121692/12122111/232326/11142121/31253151/22111111123/111313121/1111111/2151371

row31121113/12321133/13111112/13112221121/12112232/16113232/11311311/21111231/11111211/711111117/2124112211/611111241/1311371/131152131/13/2121111311/521(11)11/1311321131/1211211/11111111/14221262/3411131/161713/422141/7122117/1111112111/7111412/71111121/131112131
```

可能那个括号括起来的就是11这一个数，其他都做一位数解，并且这些数长度集中在6, 7, 8, 9, 10。

猜测题目的问题形式是数织，接下来就是Misc亲爹的个人秀：

## Misc亲爹的showtime

![img](https://pic3.zhimg.com/80/v2-00c27b01020bec039c6812be5caea656_720w.jpg)我看不懂，但我大受震撼

又由29*29推断可能是个二维码，按行打乱。根据二维码规范解出固定位置并反向更新数织。

最后只有中间部分的顺序不知道，共![[公式]](https://www.zhihu.com/equation?tex=5%21+%5Ctimes+6%21+%3D+86400)种可能性，使用程序穷举。

![img](https://pic1.zhimg.com/80/v2-f730cc2b0343f10d28ed3a515cdfc4f4_720w.jpg)这也能修，不愧是Misc亲爹

```python
data = [[1,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,1,0,0,1,0,1,1,1,1,1,1,1],
[1,0,0,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,1,1,0,1,0,0,0,0,0,1],
[1,0,1,1,1,0,1,0,1,0,1,1,1,1,1,0,0,0,0,1,1,0,1,0,1,1,1,0,1],
[1,0,1,1,1,0,1,0,0,1,0,0,1,1,1,0,0,1,1,0,1,0,1,0,1,1,1,0,1],
[1,0,1,1,1,0,1,0,1,0,0,0,0,1,0,0,0,0,1,1,0,0,1,0,1,1,1,0,1],
[1,0,0,0,0,0,1,0,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,0,0,0,0,0,1],
[1,1,1,1,1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,1,1,1,1,1,1],
[0,0,0,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[1,0,0,1,1,1,1,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,0,0,1,0,1,1,1],
[1,1,1,1,0,0,0,0,1,1,0,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,0,1],
[1,1,0,0,1,0,1,1,0,0,1,1,1,1,0,1,0,1,0,1,1,0,0,1,1,0,1,0,1],
[0,1,1,0,1,0,0,0,0,0,0,0,1,0,0,0,1,0,1,0,0,1,1,0,1,1,1,0,1],
[1,1,0,0,1,0,1,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,1,1,0,1,0,0,1],
[1,1,1,0,1,0,0,0,0,1,0,1,1,0,0,1,0,1,0,1,0,0,0,1,1,1,0,0,0],
[0,0,0,0,1,0,1,1,0,0,1,0,1,0,1,1,0,1,1,0,1,1,1,0,1,1,0,0,0],
[1,1,1,1,1,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,1,1,0,1,1,1,1,0,1],
[0,1,1,1,0,1,1,1,1,0,0,1,0,1,0,0,0,0,1,1,1,0,0,0,0,0,0,0,1],
[1,0,0,1,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,1,0,0,1,1,1,0,0],
[1,0,1,1,1,1,1,1,0,0,1,0,1,0,1,1,1,0,1,1,0,1,1,1,0,0,0,1,1],
[1,0,1,1,1,1,0,0,1,1,0,1,1,0,1,0,0,1,1,0,1,1,1,1,1,1,0,1,1],
[1,1,1,1,1,0,1,1,0,0,0,0,1,0,1,1,1,1,1,1,1,1,1,1,1,0,1,0,1],
[0,0,0,0,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,0,0,0,1,0,1,0,0],
[1,1,1,1,1,1,1,0,1,0,0,1,0,1,0,1,0,1,1,1,1,0,1,0,1,1,0,0,0],
[1,0,0,0,0,0,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,0,0,0,1,0,0,0,0],
[1,0,1,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,1,1,1,1,1,1,1,0,0,1,0],
[1,0,1,1,1,0,1,0,1,0,1,1,0,0,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1],
[1,0,1,1,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,1,0,0,1,1],
[1,0,0,0,0,0,1,0,0,0,1,0,0,1,0,0,1,0,0,1,0,1,1,0,1,0,1,0,1],
[1,1,1,1,1,1,1,0,1,0,1,0,0,0,0,1,0,0,0,0,1,0,1,1,0,1,0,0,0]]

import pyzbar.pyzbar as pyzbar
from itertools import permutations
from PIL import Image, ImageDraw as draw
import matplotlib.pyplot as plt
from tqdm import tqdm

shuffle_1 = [9, 11, 13, 15, 17, 19]
shuffle_2 = [10, 12, 14, 16, 18]
head = data[0:9]
tail = data[20:]

def body(body_1, body_2):
    body = []
    for i in range(5):
        body.append(body_1[i])
        body.append(body_2[i])
    body.append(body_1[5])
    return [data[i] for i in body]

def draw_img(data):
    assert len(data) == 29 and len(data[0]) == 29
    img = Image.new('RGB', (31, 31), (255,255,255))
    for i, row in enumerate(data):
        for j, pixel in enumerate(row):
            img.putpixel((j + 1, i + 1), (0,0,0) if pixel == 1 else (255,255,255))
    return img

with tqdm(total=720 * 120) as pbar:
    for body_1 in permutations(shuffle_1):
        for body_2 in permutations(shuffle_2):
            im = draw_img(head + body(body_1, body_2) + tail)
            barcodes = pyzbar.decode(im)
            pbar.update(1)
            if(len(barcodes) == 0):
                continue
            for barcode in barcodes:
                barcodeData = barcode.data.decode("utf-8")
                print(barcodeData)
                plt.imshow(im)
                plt.show()
```

修复成功的二维码如下图所示：

![img](https://pic3.zhimg.com/80/v2-c9be4aca7a5c7efb3d8c630e58f780c6_720w.jpg)爹中爹，代中代

## Flag

```text
flag{f31861a9-a753-47d5-8660-a8cada6c599e}
```

这一血真的，太秀了，给他倒洗脚水去了

## Reference

Writeup from [https://zhuanlan.zhihu.com/p/402713931](https://zhuanlan.zhihu.com/p/402713931)