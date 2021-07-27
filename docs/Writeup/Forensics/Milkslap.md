# Milkslap

Category: Forensics

Source: picoCTF 2021

Author: JAMES LYNCH

Score: 10

## Description

[🥛](http://mercury.picoctf.net:48380/)

## Hints

Look at the problem category

## Approach

Ctrl + shift + I on the website of milkslap and track down where the image is [located](http://mercury.picoctf.net:7585/concat_v.png)

Use the [one and only stegsolve](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve) and:

Analyze > Data Extract

then select `Blue 0` and click preview, scroll to the top:

[![solved](https://github.com/vivian-dai/PicoCTF2021-Writeup/raw/main/Forensics/Milkslap/flag.png)](https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Milkslap/flag.png)

## Flag

picoCTF{imag3_m4n1pul4t10n_sl4p5}

## Reference

Writeup from https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Milkslap/Milkslap.md