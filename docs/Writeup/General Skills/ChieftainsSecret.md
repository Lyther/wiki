# ChieftainsSecret

Category: General Skills

Source: 祥云杯2021

Author: unknown

Score: 10

## Description

Our agent risked his life to install a mysterious device in the immemorial telephone, can you find out the chieftain's telephone number? Flag format: flag{11 digits}

[ ChieftainsSecret.zip](https://compass.ctfd.io/files/8b5ca2582da75bb09a757949d91c002a/ChieftainsSecret.zip?token=eyJ1c2VyX2lkIjoxLCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjoxMDN9.YSX07A.Lmg7g6B0J8rJDkp8mMOjsKywogg)

## 题目描述

题目给了一个图种，解压得到一个电路图和两千多组数据。

## Misc亲爹的解答

结合图片推断这是转动码盘的过程记录，查阅文档可得到一系列每次码盘转动的度数。

数据可进行处理，得到sin值与cos值：

```python
def get_sin(i):
    return (data['PC0'][i] - (data['PC0'][i] + data['PC1'][i]) / 2) / 1000
def get_cos(i):
    return (data['PC2'][i] - (data['PC2'][i] + data['PC3'][i]) / 2) / 1000
```

并绘图：



![img](https://pic1.zhimg.com/80/v2-bc03799e8374f6953c8e32f6880ef538_720w.jpg)大概就是抠出峰值





![img](https://pic1.zhimg.com/80/v2-4edb358e2442038620e63eaeee366be4_720w.jpg)正弦和余弦算出后得到一个空间坐标分布



```python
_map = '1234567890'
ps = [3, 3, 0, 2, 5, 1, 4, 9, 6, 5, 3]
print(''.join([_map[i] for i in ps]))
print(''.join([_map[::-1][i] for i in ps]))
ps = [3, 3, 0, 2, 5, 1, 4, 8, 6, 5, 3]
print(''.join([_map[i] for i in ps]))
print(''.join([_map[::-1][i] for i in ps]))
```

## Flag

```text
flag{77085962457}
```

## Reference

Writeup from [https://zhuanlan.zhihu.com/p/402713931](https://zhuanlan.zhihu.com/p/402713931)