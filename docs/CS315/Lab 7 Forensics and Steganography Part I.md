# Lab 7: Forensics and Steganography Part I

> bi0s wiki: https://teambi0s.gitlab.io/bi0s-wiki/

![img](https://teambi0s.gitlab.io/bi0s-wiki/forensics/img/forensics.png)

## **Introduction**

### What is Cyber Forensics?

Cyber Forensics is a science that deals with techniques used to track the **footprints** left behind by a cyber attack. Cyber forensics is directly linked to any cybercrime which has data loss and recovery. Some examples include investigation on possible **forged digital signatures, the authenticity of images, analysis of malicious software**, etc.

Quote

Cyber Forensics is a science that deals with techniques used to track the footprints left behind by a cyber attack.

Let us go into more detail about the definition from a CTF perspective. Any Capture The Flag contest usually has three prime categories of digital forensics. They are:

- [Network Forensics](https://teambi0s.gitlab.io/forensics/network-forensics/)
- [Image Forensics](https://teambi0s.gitlab.io/forensics/image-forensics/)
- [Memory Forensics](https://teambi0s.gitlab.io/forensics/memory-forensics/)

## **Scope of Forensics**

When we talk about employment, research, or anything, Cyber Forensics is one of the prime areas which comes into a security analyst's mind. Forensics is strongly employed in **Incident Response, Malware Analysis, and Data leak protection**. To sum it up, every cybercrime is always related to cyber forensics.

To understand this, let us look into a very dangerous virus attack that almost started world war III. **Stuxnet** was a virus that was found lurking in the systems which controlled nuclear centrifuges in Iran. Stuxnet had a stolen yet officially authorized digital signature which acted as a very good camouflage. Stuxnet made the windows systems constantly reboot or lead them to **Blue Screen of Death**. Stuxnet could easily affect any computer which was linked to the network. It was really difficult for security experts to trace it. It severely affected the **SCADA systems** which were employed in maintaining the rotation speed of the centrifuges. After heavy investigation, when several forensic analysts looked into the SCADA network transfer, they found a malicious program being run that altered the system processes. The main aspect which made Stuxnet almost invisible was that it became active only when its target was present or being run. Until then the virus remained dormant. So as you can see, Cyber forensics played a huge role in the detection of the virus.

Let us look at the trend of cyber-attacks based on the analysis from January 2017-2018:

Some handy definitions:

1. **Cyber Espionage**: Use of computer networks to get access to confidential information held by important organizations.
2. **Hacktivism**: Act of hacking which is mainly done for a political purpose.
3. **Cyber Warfare**: Cyber attacks are done on state organizations to gain military secrets etc.

![alt text](https://teambi0s.gitlab.io/bi0s-wiki/forensics/img/Cyber_Attack_Stats.png) Cyber crimes are at 77% in 2017

Now let us look at January 2018: ![alt text](https://teambi0s.gitlab.io/bi0s-wiki/forensics/img/2018-analysis.png)

So as you can see, the percentage has increased at an alarming rate.

So, folks, I hope you understand just how important cyber forensics is in the current world of cybersecurity.

## **Image Forensics**

### **Introduction**

#### What is Image Forensics?

To keep it very simple and straight, **Image Forensics** is a specific branch of cyber forensics that deals with various numbers of attacks.

Some of them include:

1. The authenticity of an image
   - When we speak of authenticity, we are talking about whether the image is properly structured or not. Sometimes the data preserved inside may tamper with. Forensic analysts are required to recover this tampered data to its original state.
2. Detection of possible forgeries etc.
   - Detecting forgeries of images is a really big thing in the tech industry because many confidential images or files may be stolen or unlawfully used for criminal purposes.

So let us look into some of the very basic definitions of the technical terms used in this field to better understand the upcoming topics.

#### File Signature

A typical file signature is something that defines the nature of a file and also tells us about the specific features of the particular file. This is also called the file header or sometimes the checksum.

So let us look at some examples:

1. PNG -> **89 50 4E 47 0D 0A 1A 0A**
2. ZIP FILE -> **50 4B 03 04** or **50 4B 05 06**

The 'hex' values shown are also called **magic numbers.**

#### Chunks

Chunks are nothing but fragments of information used by different multimedia formats like **PNG, MP3**, etc. Each chunk has its header. The header usually describes the type and size of the chunk.

![img](https://teambi0s.gitlab.io/bi0s-wiki/forensics/img/Chunk_example.png)

**How important are chunks ?**

So let us consider that you are trying to open an image using an MP3 player. Will the player open the image? No, right. It'll give me an error message. Every application has a decoder that checks the type of chunks given. When it recognizes that the given chunks are supported, it tries to give the desired output. So whenever it comes across chunks of unknown format, it triggers an error message stating **"Unsupported File Format"**

#### Checksum

The checksum is an integer value that represents the sum of correct digits in a piece of data. Checksums help us to check the data integrity of a file that is transmitted across the digital network. There are many checksum algorithms. Checksum algorithms are employed in various cybersecurity concepts like **fingerprinting, cryptographic hash functions**, etc.

#### Lossless Compression

The name itself tells that there will be no loss of information when a set of data is compressed. the lossless compression technique is used for reducing the data size for storage. For example, png is a lossless compression and the advantage of a lossless compression file format is that there is no loss of quality each time it is opened or saved.

#### Lossy Compression

In lossy compression, it involves loss of information from the original file when data is compressed. Lossy compression can result in a smaller size of the file but it also removes some original pixels, video frames, and sound waves forever. For example, JPEG is a lossy compression and the disadvantage is that each time the image is saved it loses some amount of data and which simultaneously degrades the image quality.

#### Metadata Of An Image:

Image metadata is a piece of text information that gives information about the details associated with the image. Some of these details are + Size and resolution + The author of the image + The GPS data of this image + The time when the image was taken, the last modification, etc.

So now let us look at the file format of a **PNG** image:

#### Portable Network Graphics (PNG)

A PNG is a graphical file format of an image that supports **lossless compression**.

**Magic Number** -> **89 50 4E 47 0D 0A 1A 0A**

![img](https://teambi0s.gitlab.io/bi0s-wiki/forensics/img/PNG_File-Header.png) So now let us look at the critical chunks of a PNG image:

#### Critical chunks

**IHDR** -> Describes image dimensions, color type, bit depth, etc. It must be noted that this must be the first chunk (always).

**PLTE** -> Contains the list of colors.

**IDAT** -> Contains the image data.

**IEND** -> Marks the end of the image.

#### Ancillary chunks

Ancillary chunks can be otherwise called optional chunks. These are the chunks that are generally ignored by decoders. Let us look at some examples:

**bKGD** -> Gives the default background color.

**dSIG** -> This chunk is used to store the digital signature of the image.

**pHYS** -> Holds the pixel size and the ratio of dimensions of the image.

All the ancillary chunks start with a small letter.

#### Executable and Linkable Format (ELF)

The ELF file format is a standard file format for executables, object codes, core dumps, etc. for any UNIX-based system.

**Magic Number** -> **7F 45 4c 46**

The file header of an ELF file defines whether to use 32-bit or 64-bit addresses. ELF files are generally analyzed using a tool called **readelf**.

#### ZIP

Zip is a file format that supports lossless data compression. This file format achieves the compression of a file(s) using several compression algorithms. DEFLATE is the most used compression algorithm. Zip files have the file extension .zip or .ZIP.

**Magic Number** -> **50 4B 03 04** and **50 4B 05 06**(for empty zip files)

![img](https://teambi0s.gitlab.io/bi0s-wiki/forensics/img/zip.png)

Zip files can be extracted using this command in the terminal.

```
$ unzip file_name.zip
```

## Least Significant Bit Encoding

### Definition

**What is LSB ?**

**LSB**, the **least significant bit** is the lowest in a series of numbers in binary; which is located at the far right of a string. For example, in the binary number: 10111001, the least significant bit is the far right 1.

As binary numbers are largely used in computing and other related areas, wherein the least significant bit holds importance, especially when it comes to the transmission of binary numbers.

Digital data is computed in binary format, where the rightmost digit is considered the lowest digit whereas the leftmost is considered the highest digit. In positional notation, the least significant bit is also known as the rightmost bit. It is the opposite of the most significant bit, which carries the highest value in a multiple-bit binary number as well as the number which is farthest to the right. In a multi-bit binary number, the significance of a bit decreases as it approaches the least significant bit. Since it is binary, the most significant bit can be either 1 or 0. The least significant bit is frequently employed in hash functions, checksums, and pseudorandom number generators.

When transmission of binary data is being done, the least significant bit is the one that is transmitted first, followed by other bits of increasing significance.

The number of image pixels in a **PNG** file is generally composed of **RGB** three primary colors (red, green, and blue). Each color occupies 8 bits, and the value ranges from 0x00 to 0xFF, that is, there are 256 colors, which contain a total of 256 to the third power. Thus there are 16777216 colors in total.

The human eye can distinguish about 10 million different colors, which means that the human eye can't distinguish the remaining 6 million colors. LSB steganography is to modify the lowest binary bit (LSB) of RGB color components, each color will have 8 bits, LSB steganography is to modify the lowest bit in the number of pixels, and human eyes will not notice before and after this change, each pixel can carry 3 bits of information.

### Example

#### PicoCTF_2017: Little School Bus

**Description:**

Can you help me find the data in this [Little-School-Bus](https://teambi0s.gitlab.io/forensics/img/lb.bmp)?

**Hint:**

Look at least a significant bit of encoding!!

##### Solution

As the Hint suggests the problem is related to LSB Encoding, The leftmost digit in binary is called the LSB digit

As mentioned earlier LSB encoding is done by changing the LSB bit of the color, however, this slight variation is not noticeable. Thus by changing the LSB bit, we can hide data inside a file.

```
xxd -b ./littleschoolbus.bmp | head -n 20
```

Gives,

```
00000000: 01000010 01001101 11100010 01001011 00000010 00000000  BM.K...
00000006: 00000000 00000000 00000000 00000000 00110110 00000000  ....6.
0000000c: 00000000 00000000 00101000 00000000 00000000 00000000  ..(...
00000012: 11111100 00000000 00000000 00000000 11000111 00000000  ......
00000018: 00000000 00000000 00000001 00000000 00011000 00000000  ......
0000001e: 00000000 00000000 00000000 00000000 10101100 01001011  .....K
00000024: 00000010 00000000 00000000 00000000 00000000 00000000  ......
0000002a: 00000000 00000000 00000000 00000000 00000000 00000000  ......
00000030: 00000000 00000000 00000000 00000000 00000000 00000000  ......
00000036: 11111110 11111111 11111111 11111110 11111110 11111111  ......
0000003c: 11111111 11111110 11111110 11111111 11111111 11111110  ......
00000042: 11111111 11111111 11111110 11111110 11111110 11111111  ......
00000048: 11111111 11111110 11111110 11111110 11111110 11111111  ......
0000004e: 11111110 11111111 11111111 11111110 11111110 11111111  ......
00000054: 11111111 11111111 11111110 11111111 11111111 11111111  ......
0000005a: 11111111 11111110 11111111 11111111 11111110 11111111  ......
00000060: 11111111 11111111 11111110 11111110 11111111 11111110  ......
00000066: 11111110 11111111 11111111 11111110 11111110 11111111  ......
0000006c: 11111110 11111111 11111110 11111111 11111111 11111110  ......
00000072: 11111111 11111111 11111110 11111111 11111110 11111111  ......
```

Taking the LSB bit after the many zeros,

```
00000036: 11111110 11111111 11111111 11111110 11111110 11111111  ......
0000003c: 11111111 11111110 11111110 11111111 11111111 11111110  ......
00000042: 11111111 11111111 11111110 11111110 11111110 11111111  ......
00000048: 11111111 11111110 11111110 11111110 11111110 11111111  ......
```

8 bit gives

```
01100110 01101100
```

Which in ASCII is `fl`?

Now we script,

```
binary_data = open("littleschoolbus.bmp","rb") # Open the file binary mode
binary_data.seek(54)  #seek to 54 bytes these bytes do not contain any data
data = binary_data.read() # read the binary data
l = []
for i in data:
    l.append(bin(i)[-1])  #make a list of LSB bit
for i in range(0,500,8):
    print(chr(int(''.join(l[i:i+8]),2)),end='') # print the character
```

Which gives the flag !!

flag{remember_kids_protect_your_headers_afb3}

##### Footnote :

1. [LSB](http://www.aaronmiller.in/thesis/)
2. [Python Binary File I/O](http://www.devdungeon.com/content/working-binary-data-python)

## **Assignment**

Let's play with some real CTF challenges!

> Buckeye CTF 2022

### **(1 - easy) what-you-see-is-what-you-git**

Author: matthewa26

I definitely made a Git repo, but I somehow broke it. Something about not getting a HEAD of myself.

Downloads: [what-you-see-is-what-you-git](static/what-you-see-is-what-you-git.zip)

### **(2 - easy) sus**

Author: gsemaj

Something about this audio is pretty *sus*...

Hint: The crackling in the audio should tell you that something's wrong.

Downloads: [sus.wav](static/sus.wav)

### **(3 - medium) keyboardwarrior**

Author: v0rtex

I found a PCAP of some Bluetooth packets being sent on this guy's computer. He's sending some pretty weird stuff, you should take a look.

Flag format: buckeyectf{x}

Downloads: [keyboardwarrior](static/keyboardwarrior.pcap)