# Wireshark doo dooo do doo...

Category: Forensics

Source: picoCTF 2021

Author: DYLAN

Score: 5

## Description

Can you find the flag? [shark1.pcapng](https://mercury.picoctf.net/static/ae5b2bc07928fca272ff3900dc9a6cef/shark1.pcapng).

## Hints

(None)

## Approach

I opened [shark1.pcapng](https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Wireshark doo dooo do doo/shark1.pcapng) with [Wireshark](https://www.wireshark.org/). I followed the TCP stream:

[![screenshot](https://github.com/vivian-dai/PicoCTF2021-Writeup/raw/main/Forensics/Wireshark%20doo%20dooo%20do%20doo/screenshot.png)](https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Wireshark doo dooo do doo/screenshot.png)

Stream 5 (`tcp.stream eq 5`) contained something that looked promising

> Gur synt vf cvpbPGS{c33xno00_1_f33_h_qrnqorrs}

After decoding that with [ROT13](https://rot13.com/), the flag was revealed.

## Flag

picoCTF{p33kab00_1_s33_u_deadbeef}

## Reference

Writeup from https://github.com/vivian-dai/PicoCTF2021-Writeup/blob/main/Forensics/Wireshark%20doo%20dooo%20do%20doo/Wireshark%20doo%20dooo%20do%20doo.md

