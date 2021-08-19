# xixixi

Category: General Skills

Source: 祥云杯2020

Author: unknown

Score: 50

## Description

室友最近沉迷y神，又氪又肝，还ghs。为了他的身体着想，我把他的s图整没了。但我明明删了脚本啊，为什么还能被他发现......8说了，医院的空调真舒服~

## Solution

磁盘内所有内容如下：（可用winhex直接复原）

```python
# !i.py


import struct
from xixi import FAT32Parser
from xixixi import Padding, picDepartList


def EncodePieces():
  global clusterList
  res = []
  Range = len(picDepartList)    # 58
  # GetRandomClusterList(n) - Generate a random cluster list with length n
  clusterList = GetRandomClusterList(Range)


  for i in range(Range):
    if i != Range - 1:
      newCRC = struct.pack("<I", clusterList[i+1])
      plainData = picDepartList[i][:-4] + newCRC
    else:
      plainData = picDepartList[i]


    # Show the first piece to him, hhh
    if i == 0:
      newPiece = plainData
    else:
      newPiece = ''
      key = clusterList[i] & 0xFE
      for j in plainData:
        newPiece += chr(ord(j) ^ key)
    # Padding() -- Fill to an integral multiple of 512 with \xFF
    res.append(Padding(newPiece))
  return res
```

```python
# !ixi.py


import struct


class FAT32Parser(object):
  def __init__(self, vhdFileName):
    with open(vhdFileName, 'rb') as f:
      self.diskData = f.read()
    self.DBR_off = self.GetDBRoff()
    self.newData = ''.join(self.diskData)


  def GetDBRoff(self):
    DPT_off = 0x1BE
    target = self.diskData[DPT_off+8:DPT_off+12]
    DBR_sector_off, = struct.unpack("<I", target)
    return DBR_sector_off * 512


  def GetFAT1off(self):
    target = self.diskData[self.DBR_off+0xE:self.DBR_off+0x10]
    FAT1_sector_off, = struct.unpack("<H", target)
    return self.DBR_off + FAT1_sector_off * 512


  def GetFATlength(self):
    target = self.diskData[self.DBR_off+0x24:self.DBR_off+0x28]
    FAT_sectors, = struct.unpack("<I", target)
    return FAT_sectors * 512


  def GetRootoff(self):
    FAT_length = self.GetFATlength()
    FAT2_off = self.GetFAT1off() + FAT_length
    return FAT2_off + FAT_length


  def Cluster2FAToff(self, cluster):
    FAT1_off = self.GetFAT1off()
    return FAT1_off + cluster * 4


  def Cluster2DataOff(self, cluster):
    rootDir_off = self.GetRootoff()
    return rootDir_off + (cluster - 2) * 512
```

分析两个文件，可以得出：

!ixi.py中的类FAT32Parser，可以对磁盘进行一系列操作。!i.py中的文件是对文件进行分块儿处理，并且图片被分为了58块儿，除了第一块儿未被加密外，其余块儿都进行了如下处理：

1. 每块儿的最后四位，即CRC校验值被替换成了下一块儿所在的簇号。

2. 除第一块儿外，其余块儿的内容都会与该块儿的簇号 & 0xFE整体进行异或。

所以想要反解图片块儿，需要对每个块儿先进行异或解密，再查看后四位得到下一块儿的簇号。

```python
# -*- coding: utf-8 -*-
# @Project: Hello Python!
# @File   : exp
# @Author : Tr0jAn <Tr0jAn@birkenwald.cn>
# @Date   : 2020-11-22
import struct
import binascii
from xixi import FAT32Parser


def read(n):
    global key
    binary = b''
    for i in vhd.read(n):
        binary += (i ^ (key & 0xFE)).to_bytes(length=1, byteorder='big', signed=False)
    return binary


FAT = FAT32Parser("new.vhd")
vhd = open("new.vhd", "rb")
vhd.seek(0x27bae00)  # 定位磁盘中图片位置
flag = open("flag.png", "wb")
flag.write(vhd.read(8))  # 写入png头
key = 0
while True:
    d = read(8)
    length, cType = struct.unpack(">I4s", d)
    print(length, cType)  # length为数据长度，cType为数据块类型
    data = read(length)
    CRC = struct.unpack(">I", read(4))[0]
    print(CRC)
    rCRC = binascii.crc32(cType + data) & 0xffffffff
    print(rCRC)
    rDATA = struct.pack(">I", length) + cType + data + struct.pack(">I", rCRC)
    flag.write(rDATA)
    if CRC != rCRC:  # CRC错误的IDAT数据块
        b_endian = struct.pack(">I", CRC)
        clusterList = struct.unpack("<I", b_endian)[0]
        print(clusterList)
        vhd.seek(FAT.Cluster2DataOff(clusterList))
        key = clusterList & 0xFE
    if cType == b"IEND":
        break
```

对磁盘反解出flag.png

![图片](https://mmbiz.qpic.cn/mmbiz_png/VfLUYJEMVsiaStUACcrx4rzlvPxdklxllO44ssAQxxk1zCzDtUptC0GWm7dJl96enN6a0Olzdp5RUxVDiav6pibbw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)    

## Flag

flag{0cfdd1ad80807da6c0413de606bb0ae4}

## Reference

Writeup from [https://mp.weixin.qq.com/s/0b9nQRxkbu7mDPji_Y8Ghw](https://mp.weixin.qq.com/s/0b9nQRxkbu7mDPji_Y8Ghw)