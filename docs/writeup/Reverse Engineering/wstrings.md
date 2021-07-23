# wstrings

Category: Reverse Engineering

Source: redpwn CTF 2021

Author: NotDeGhost

Score: 5

## Description

Some strings are wider than normal...

Author : NotDeGhost

[wstrings](https://github.com/BaadMaro/CTF/blob/main/redpwnCTF 2021/REV - wstrings/wstrings)

## Detailed solution

As the description mention let's start by checking file strings

At offest 0x930 we can see our flag

```
~# hexdump -n 140 -s 0x930 -C wstrings
00000930  01 00 02 00 00 00 00 00  66 00 00 00 6c 00 00 00  |........f...l...|
00000940  61 00 00 00 67 00 00 00  7b 00 00 00 6e 00 00 00  |a...g...{...n...|
00000950  30 00 00 00 74 00 00 00  5f 00 00 00 61 00 00 00  |0...t..._...a...|
00000960  6c 00 00 00 31 00 00 00  5f 00 00 00 73 00 00 00  |l...1..._...s...|
00000970  74 00 00 00 72 00 00 00  31 00 00 00 6e 00 00 00  |t...r...1...n...|
00000980  67 00 00 00 73 00 00 00  5f 00 00 00 61 00 00 00  |g...s..._...a...|
00000990  72 00 00 00 33 00 00 00  5f 00 00 00 73 00 00 00  |r...3..._...s...|
000009a0  6b 00 00 00 31 00 00 00  6e 00 00 00 6e 00 00 00  |k...1...n...n...|
000009b0  79 00 00 00 7d 00 00 00  00 00 00 00              |y...}.......|
000009bc
```

## Flag

```
flag{n0t_al1_str1ngs_ar3_sk1nny}
```

## Reference

Writeup from https://github.com/BaadMaro/CTF/tree/main/redpwnCTF%202021/REV%20-%20wstrings