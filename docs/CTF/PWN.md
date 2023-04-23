# Binary Exploitation

> https://ctf101.org/binary-exploitation/overview/

Binaries, or executables, are machine codes for a computer to execute. For the most part, the binaries that you will face in CTFs are Linux ELF files or the occasional Windows executable. Binary Exploitation is a broad topic within Cyber Security that really comes down to finding a vulnerability in the program and exploiting it to gain control of a shell or modifying the program's functions.

Common topics addressed by Binary Exploitation or 'pwn' challenges include:

- Registers
- The Stack
- Calling Conventions
- Global Offset Table (GOT)
- Buffers
  - Buffer Overflow
- Return Oriented Programming (ROP)
- Binary Security
  - No eXecute (NX)
  - Address Space Layout Randomization (ASLR)
  - Stack Canaries
  - Relocation Read-Only (RELRO)
- The Heap
  - Heap Exploitation
- Format String Vulnerability

## Registers

A **register** is a location within the processor that is able to store data, much like RAM. Unlike RAM, however, accesses to registers are effectively instantaneous, whereas reads from main memory can take hundreds of CPU cycles to return.

Registers can hold any value: addresses (pointers), results from mathematical operations, characters, etc. Some registers are *reserved* however, meaning they have a special purpose and are not "general purpose registers" (GPRs). On x86, the only 2 reserved registers are `rip` and `rsp` which hold the address of the next instruction to execute and the address of the stack respectively.

On x86, the same register can have different-sized accesses for backward compatibility. For example, the `rax` register is the full 64-bit register, `eax` is the low 32 bits of `rax`, `ax` is the low 16 bits, `al` is the low 8 bits, and `ah` is the high 8 bits of `ax` (bits 8-16 of `rax`).

## The Stack

In computer architecture, the stack is a hardware manifestation of the stack data structure (a Last In, First Out queue).

In x86, the stack is simply an area in RAM that was chosen to be the stack - there is no special hardware to store stack contents. The `esp`/`rsp` register holds the address in memory where the bottom of the stack resides. When something is `push`ed to the stack, `esp` decrements by 4 (or 8 on 64-bit x86), and the value that was `push`ed is stored at that location in memory. Likewise, when a `pop` instruction is executed, the value at `esp` is retrieved (i.e. `esp` is dereferenced), and `esp` is then incremented by 4 (or 8).

**N.B. The stack "grows" down to lower memory addresses!**

Conventionally, `ebp`/`rbp` contains the address of the top of the current **stack frame**, and so sometimes local variables are referenced as an offset relative to `ebp` rather than an offset to `esp`. A stack frame is essentially just the space used on the stack by a given function.

### Uses

The stack is primarily used for a few things:

- Storing function arguments
- Storing local variables
- Storing processor state between function calls

### Example

Let's see what the stack looks like right after `say_hi` has been called in this 32-bit x86 C program:

```
#include <stdio.h>

void say_hi(const char * name) {
    printf("Hello %s!\n", name);
}

int main(int argc, char ** argv) {
    char * name;
    if (argc != 2) {
        return 1;
    }
    name = argv[1];
    say_hi(name);
    return 0;
}
```

And the relevant assembly:

```
0804840b <say_hi>:
 804840b:   55                      push   ebp
 804840c:   89 e5                   mov    ebp,esp
 804840e:   83 ec 08                sub    esp,0x8
 8048411:   83 ec 08                sub    esp,0x8
 8048414:   ff 75 08                push   DWORD PTR [ebp+0x8]
 8048417:   68 f0 84 04 08          push   0x80484f0
 804841c:   e8 bf fe ff ff          call   80482e0 <printf@plt>
 8048421:   83 c4 10                add    esp,0x10
 8048424:   90                      nop
 8048425:   c9                      leave
 8048426:   c3                      ret

08048427 <main>:
 8048427:   8d 4c 24 04             lea    ecx,[esp+0x4]
 804842b:   83 e4 f0                and    esp,0xfffffff0
 804842e:   ff 71 fc                push   DWORD PTR [ecx-0x4]
 8048431:   55                      push   ebp
 8048432:   89 e5                   mov    ebp,esp
 8048434:   51                      push   ecx
 8048435:   83 ec 14                sub    esp,0x14
 8048438:   89 c8                   mov    eax,ecx
 804843a:   83 38 02                cmp    DWORD PTR [eax],0x2
 804843d:   74 07                   je     8048446 <main+0x1f>
 804843f:   b8 01 00 00 00          mov    eax,0x1
 8048444:   eb 1c                   jmp    8048462 <main+0x3b>
 8048446:   8b 40 04                mov    eax,DWORD PTR [eax+0x4]
 8048449:   8b 40 04                mov    eax,DWORD PTR [eax+0x4]
 804844c:   89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 804844f:   83 ec 0c                sub    esp,0xc
 8048452:   ff 75 f4                push   DWORD PTR [ebp-0xc]
 8048455:   e8 b1 ff ff ff          call   804840b <say_hi>
 804845a:   83 c4 10                add    esp,0x10
 804845d:   b8 00 00 00 00          mov    eax,0x0
 8048462:   8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 8048465:   c9                      leave
 8048466:   8d 61 fc                lea    esp,[ecx-0x4]
 8048469:   c3                      ret
```

Skipping over the bulk of `main`, you'll see that at `0x8048452` `main`'s `name` local is pushed to the stack because it's the first argument to `say_hi`. Then, a `call` instruction is executed. `call` instructions first push the current instruction pointer to the stack, then jump to their destination. So when the processor begins executing `say_hi` at `0x0804840b`, the stack looks like this:

```
EIP = 0x0804840b (push ebp)
ESP = 0xffff0000
EBP = 0xffff002c

        0xffff0004: 0xffffa0a0              // say_hi argument 1
ESP ->  0xffff0000: 0x0804845a              // Return address for say_hi
```

The first thing `say_hi` does is save the current `ebp` so that when it returns, `ebp` is back where `main` expects it to be. The stack now looks like this:

```
EIP = 0x0804840c (mov ebp, esp)
ESP = 0xfffefffc
EBP = 0xffff002c

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
ESP ->  0xfffefffc: 0xffff002c              // Saved EBP
```

Again, note how `esp` gets smaller when values are pushed to the stack.

Next, the current `esp` is saved into `ebp`, marking the top of the new stack frame.

```
EIP = 0x0804840e (sub esp, 0x8)
ESP = 0xfffefffc
EBP = 0xfffefffc

            0xffff0004: 0xffffa0a0              // say_hi argument 1
            0xffff0000: 0x0804845a              // Return address for say_hi
ESP, EBP -> 0xfffefffc: 0xffff002c              // Saved EBP
```

Then, the stack is "grown" to accommodate local variables inside `say_hi`.

```
EIP = 0x08048414 (push [ebp + 0x8])
ESP = 0xfffeffec
EBP = 0xfffefffc

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
EBP ->  0xfffefffc: 0xffff002c              // Saved EBP
        0xfffefff8: UNDEFINED
        0xfffefff4: UNDEFINED
        0xfffefff0: UNDEFINED
ESP ->  0xfffefffc: UNDEFINED
```

**NOTE: stack space is not implicitly cleared!**

Now, the 2 arguments to `printf` are pushed in reverse order.

```
EIP = 0x0804841c (call printf@plt)
ESP = 0xfffeffe4
EBP = 0xfffefffc

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
EBP ->  0xfffefffc: 0xffff002c              // Saved EBP
        0xfffefff8: UNDEFINED
        0xfffefff4: UNDEFINED
        0xfffefff0: UNDEFINED
        0xfffeffec: UNDEFINED
        0xfffeffe8: 0xffffa0a0              // printf argument 2
ESP ->  0xfffeffe4: 0x080484f0              // printf argument 1
```

Finally, `printf` is called, which pushes the address of the next instruction to execute.

```
EIP = 0x080482e0
ESP = 0xfffeffe4
EBP = 0xfffefffc

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
EBP ->  0xfffefffc: 0xffff002c              // Saved EBP
        0xfffefff8: UNDEFINED
        0xfffefff4: UNDEFINED
        0xfffefff0: UNDEFINED
        0xfffeffec: UNDEFINED
        0xfffeffe8: 0xffffa0a0              // printf argument 2
        0xfffeffe4: 0x080484f0              // printf argument 1
ESP ->  0xfffeffe0: 0x08048421              // Return address for printf
```

Once `printf` has returned, the `leave` instruction moves `ebp` into `esp`, and pops the saved EBP.

```
EIP = 0x08048426 (ret)
ESP = 0xfffefffc
EBP = 0xffff002c

        0xffff0004: 0xffffa0a0              // say_hi argument 1
ESP ->  0xffff0000: 0x0804845a              // Return address for say_hi
```

And finally, `ret` pops the saved instruction pointer into `eip` which causes the program to return to main with the same `esp`, `ebp`, and stack contents as when `say_hi` was initially called.

```
EIP = 0x0804845a (add esp, 0x10)
ESP = 0xffff0000
EBP = 0xffff002c

ESP ->  0xffff0004: 0xffffa0a0              // say_hi argument 1
```

## Calling Conventions

To be able to call functions, there needs to be an agreed-upon way to pass arguments. If a program is entirely self-contained in a binary, the compiler would be free to decide the calling convention. However, in reality, shared libraries are used so that common code (e.g. libc) can be stored once and dynamically linked into programs that need it, reducing program size.

In Linux binaries, there are really only two commonly used calling conventions: cdecl for 32-bit binaries, and SysV for 64-bit

### cdecl

In 32-bit binaries on Linux, function arguments are passed in on the stack in reverse order. A function like this:

```
int add(int a, int b, int c) {
    return a + b + c;
}
```

would be invoked by pushing `c`, then `b`, then `a`.

### SysV

For 64-bit binaries, function arguments are first passed in certain registers:

1. RDI
2. RSI
3. RDX
4. RCX
5. R8
6. R9

then any leftover arguments are pushed onto the stack in reverse order, as in cdecl.

### Other Conventions

Any method of passing arguments could be used as long as the compiler is aware of what the convention is. As a result, there have been *many* calling conventions in the past that aren't used frequently anymore. See [Wikipedia](https://en.wikipedia.org/wiki/X86_calling_conventions) for a comprehensive list.

## GOT

The Global Offset Table (or GOT) is a section inside of programs that hold addresses of functions that are dynamically linked. As mentioned in the page on calling conventions, most programs don't include every function they use to reduce binary size. Instead, common functions (like those in libc) are "linked" into the program so they can be saved once on disk and reused by every program.

Unless a program is marked full RELRO, the resolution of the function to address in a dynamic library is done lazily. All dynamic libraries are loaded into memory along with the main program at launch, however, functions are not mapped to their actual code until they're first called. For example, in the following C snippet `puts` won't be resolved to an address in libc until after it has been called once:

```
int main() {
    puts("Hi there!");
    puts("Ok bye now.");
    return 0;
}
```

To avoid searching through shared libraries each time a function is called, the result of the lookup is saved into the GOT so future function calls "short circuit" straight to their implementation bypassing the dynamic resolver.

This has two important implications:

1. The GOT contains pointers to libraries which move around due to ASLR
2. The GOT is writable

These two facts will become very useful to use in Return Oriented Programming

### PLT

Before the address of a function has been resolved, the GOT points to an entry in the Procedure Linkage Table (PLT). This is a small "stub" function that is responsible for calling the dynamic linker with (effectively) the name of the function that should be resolved.

## Buffers

A buffer is any allocated space in memory where data (often user input) can be stored. For example, in the following C program `name` would be considered a stack buffer:

```
#include <stdio.h>

int main() {
    char name[64] = {0};
    read(0, name, 63);
    printf("Hello %s", name);
    return 0;
}
```

Buffers could also be global variables:

```
#include <stdio.h>

char name[64] = {0};

int main() {
    read(0, name, 63);
    printf("Hello %s", name);
    return 0;
}
```

Or dynamically allocated on the heap:

```
#include <stdio.h>
#include <stdlib.h>

int main() {
    char *name = malloc(64);
    memset(name, 0, 64);
    read(0, name, 63);
    printf("Hello %s", name);
    return 0;
}
```

### Exploits

Given that buffers commonly hold user input, mistakes when writing to them could result in attacker-controlled data being written outside of the buffer's space. See the page on buffer overflows for more.

## Buffer Overflow

A Buffer Overflow is a vulnerability in which data can be written that exceeds the allocated space, allowing an attacker to overwrite other data.

### Stack buffer overflow

The simplest and most common buffer overflow is one where the buffer is on the stack. Let's look at an example.

```
#include <stdio.h>

int main() {
    int secret = 0xdeadbeef;
    char name[100] = {0};
    read(0, name, 0x100);
    if (secret == 0x1337) {
        puts("Wow! Here's a secret.");
    } else {
        puts("I guess you're not cool enough to see my secret");
    }
}
```

There's a tiny mistake in this program which will allow us to see the secret. `name` is decimal 100 bytes, however, we're reading in hex 100 bytes (=256 decimal bytes)! Let's see how we can use this to our advantage.

If the compiler chose to layout the stack like this:

```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0xdeadbeef  // secret
...
        0xffff0004: 0x0
ESP ->  0xffff0000: 0x0         // name
```

let's look at what happens when we read in 0x100 bytes of 'A's.

The first decimal 100 bytes are saved properly:

```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0xdeadbeef  // secret
...
        0xffff0004: 0x41414141
ESP ->  0xffff0000: 0x41414141  // name
```

However, when the 101st byte is read in, we see an issue:

```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0xdeadbe41  // secret
...
        0xffff0004: 0x41414141
ESP ->  0xffff0000: 0x41414141  // name
```

The least significant byte of the `secret` has been overwritten! If we follow the next 3 bytes to be read in, we'll see the entirety of the `secret` is "clobbered" with our 'A's

```
        0xffff006c: 0xf7f7f7f7  // Saved EIP
        0xffff0068: 0xffff0100  // Saved EBP
        0xffff0064: 0x41414141  // secret
...
        0xffff0004: 0x41414141
ESP ->  0xffff0000: 0x41414141  // name
```

The remaining 152 bytes would continue clobbering values up the stack.

#### Passing an impossible check

How can we use this to pass the seemingly impossible check in the original program? Well, if we carefully line up our input so that the bytes that overwrite the `secret` happen to be the bytes that represent 0x1337 in Little Endian, we'll see the secret message.

A small Python one-liner will work nicely: `python -c "print 'A'*100 + '\x31\x13\x00\x00'"`

This will fill the `name` buffer with 100 'A's, then overwrite the `secret` with the 32-bit little-endian encoding of 0x1337.

#### Going one step further

As discussed on [the stack](https://ctf101.org/binary-exploitation/what-is-the-stack) page, the instruction that the current function should jump to when it is done is also saved on the stack (denoted as "Saved EIP" in the above stack diagrams). If we can overwrite this, we can control where the program jumps after the `main` finishes running, giving us the ability to control what the program does entirely.

Usually, the end objective in binary exploitation is to get a shell (often called "popping a shell") on the remote computer. The shell provides us with an easy way to run *anything* we want on the target computer.

Say there happens to be a nice function that does this define somewhere else in the program that we normally can't get to:

```
void give_shell() {
    system("/bin/sh");
}
```

Well with our buffer overflow knowledge, now we can! All we have to do is overwrite the saved EIP on the stack to the address where `give_shell` is. Then, when the main returns, it will pop that address off of the stack and jump to it, running `give_shell`, and giving us our shell.

Assuming `give_shell` is at 0x08048fd0, we could use something like this: `python -c "print 'A'*108 + '\xd0\x8f\x04\x08'"`

We send 108 'A's to overwrite the 100 bytes that are allocated for the `name`, the 4 bytes for `secret`, and the 4 bytes for the saved EBP. Then we simply send the little-endian form of `give_shell`'s address, and we would get a shell!

This idea is extended on in Return Oriented Programming

## Return Oriented Programming

Return Oriented Programming (or ROP) is the idea of chaining together small snippets of assembly with stack control to cause the program to do more complex things.

As we saw in buffer overflows, having stack control can be very powerful since it allows us to overwrite saved instruction pointers, giving us control over what the program does next. Most programs don't have a convenient `give_shell` function, however, so we need to find a way to manually invoke the `system` or another `exec` function to get us our shell.

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

We obviously have a stack buffer overflow on the `echo` variable which can give us EIP control when the `main` returns. But we don't have a `give_shell` function! So what can we do?

We can call the `system` with an argument we control! Since arguments are passed in on the stack in 32-bit Linux programs (see [calling conventions](https://ctf101.org/binary-exploitation/what-are-calling-conventions)), if we have stack control, we have argument control.

When the main returns, we want our stack to look like something normally called `system`. Recall what is on the stack after a function has been called:

```
        ...                                 // More arguments
        0xffff0008: 0x00000002              // Argument 2
        0xffff0004: 0x00000001              // Argument 1
ESP ->  0xffff0000: 0x080484d0              // Return address
```

So the `main`'s stack frame needs to look like this:

```
        0xffff0008: 0xdeadbeef              // system argument 1
        0xffff0004: 0xdeadbeef              // return address for system
ESP ->  0xffff0000: 0x08048450              // return address for main (system's PLT entry)
```

Then when the `main` returns, it will jump into the `system`'s PLT entry and the stack will appear just like the `system` had been called normally for the first time.

Note: we don't care about the return address `system` will return to because we will have already gotten our shell by then!

#### Arguments

This is a good start, but we need to pass an argument to the `system` for anything to happen. As mentioned in the page on [ASLR](https://ctf101.org/binary-exploitation/address-space-layout-randomization), the stack and dynamic libraries "move around" each time a program is run, which means we can't easily use data on the stack or a string in libc for our argument. In this case, however, we have a very convenient `name` global which will be at a known location in the binary (in the BSS segment).

#### Putting it together

Our exploit will need to do the following:

1. Enter "sh" or another command to run as the `name`
2. Fill the stack with
   1. Garbage up to the saved EIP
   2. The address of the `system`'s PLT entry
   3. A fake return address for the system to jump to when it's done
   4. The address of the `name` global acts as the first argument to the `system`

### 64 bit

In 64-bit binaries, we have to work a bit harder to pass arguments to functions. The basic idea of overwriting the saved RIP is the same, but as discussed in calling conventions, arguments are passed in registers in 64-bit programs. In the case of running the `system`, this means we will need to find a way to control the RDI register.

To do this, we'll use small snippets of assembly in the binary, called "gadgets." These gadgets usually `pop` one or more registers off of the stack, and then call `ret`, which allows us to chain them together by making a large fake call stack.

For example, if we needed control of both RDI and RSI, we might find two gadgets in our program that look like this (using a tool like [rp++](https://github.com/0vercl0k/rp) or [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)):

```
0x400c01: pop rdi; ret
0x400c03: pop rsi; pop r15; ret
```

We can set up a fake call stack with these gadgets to sequentially execute them, `pop`ing values we control into registers, and then end with a jump to the `system`.

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

## Binary Security

Binary Security is using tools and methods in order to secure programs from being manipulated and exploited. These tools are not infallible, but when used together and implemented properly, they can raise the difficulty of exploitation greatly.

Some methods covered include:

- [No eXecute (NX)](https://ctf101.org/binary-exploitation/no-execute/)
- [Address Space Layout Randomization (ASLR)](https://ctf101.org/binary-exploitation/address-space-layout-randomization/)
- [Relocation Read-Only (RELRO)](https://ctf101.org/binary-exploitation/relocation-read-only/)
- [Stack Canaries/Cookies](https://ctf101.org/binary-exploitation/stack-canaries/)

## The Heap

A **heap** is a place in memory that a program can use to dynamically create objects. Creating objects on the heap has some advantages compared to using the stack:

- Heap allocations can be dynamically sized
- Heap allocations "persist" when a function returns

There are also some disadvantages, however:

- Heap allocations can be slower
- Heap allocations must be manually cleaned up

### Using the heap

In C, there are a number of functions used to interact with the heap, but we're going to focus on the two core ones:

- `malloc`: allocate `n` bytes on the heap
- `free`: free the given allocation

Let's see how these could be used in a program:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    unsigned alloc_size = 0;
    char *stuff;

    printf("Number of bytes? ");
    scanf("%u", &alloc_size);

    stuff = malloc(alloc_size + 1);
    memset(0, stuff, alloc_size + 1);

    read(0, stuff, alloc_size);

    printf("You wrote: %s", stuff);

    free(stuff);

    return 0;
}
```

This program reads in a size from the user, creates an allocation of that size on the heap, reads in that many bytes, then prints it back out to the user.

## Heap Exploits

### Overflow

Much like a [stack buffer overflow](https://ctf101.org/binary-exploitation/buffer-overflow/#stack-buffer-overflow), a **heap overflow** is a vulnerability where more data than can fit in the allocated buffer is read in. This could lead to heap metadata corruption, or corruption of other heap objects, which could in turn provide a new attack surface.

### Use After Free (UAF)

Once `free` is called on an allocation, the allocator is free to reallocate that chunk of memory in future calls to `malloc` if it so chooses. However, if the program author isn't careful and uses the freed object later on, the contents may be corrupt (or even attacker controlled). This is called use after free or UAF.

#### Example

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct string {
    unsigned length;
    char *data;
} string;

int main() {
    struct string* s = malloc(sizeof(string));
    puts("Length:");
    scanf("%u", &s->length);
    s->data = malloc(s->length + 1);
    memset(s->data, 0, s->length + 1);
    puts("Data:");
    read(0, s->data, s->length);

    free(s->data);
    free(s);

    char *s2 = malloc(16);
    memset(s2, 0, 16);
    puts("More data:");
    read(0, s2, 15);

    // Now using s again, a UAF

    puts(s->data);

    return 0;
}
```

In this example, we have a `string` structure with a length and a pointer to the actual string data. We properly allocate, fill, and then free an instance of this structure. Then we make another allocation, fill it, and then improperly reference the freed `string`. Due to how Glibc's allocator works, `s2` will actually get the same memory as the original `s` allocation, which in turn gives us the ability to control the `s->data` pointer. This could be used to leak program data.

## Advanced Heap Exploitation

Not only can the heap be exploited by the data in allocations, but exploits can also use the underlying mechanisms in `malloc`, `free`, etc. to exploit a program. This is beyond the scope of CTF 101, but here are a few recommended resources:

- [sploitFUN's glibc overview](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
- [Shellphish's how2heap](https://github.com/shellphish/how2heap)

## Format String Vulnerability

A format string vulnerability is a bug where user input is passed as the format argument to `printf`, `scanf`, or another function in that family.

The format argument has many different specifies which could allow an attacker to leak data if they control the format argument to `printf`. Since `printf` and similar are *variadic* functions, they will continue popping data off of the stack according to the format.

For example, if we can make the format argument "%x.%x.%x.%x", `printf` will pop off four stack values and print them in hexadecimal, potentially leaking sensitive information.

`printf` can also index to an arbitrary "argument" with the following syntax: "%n$x" (where `n` is the decimal index of the argument you want).

While these bugs are powerful, they're very rare nowadays, as all modern compilers warn when `printf` is called with a non-constant string.

### Example

```
#include <stdio.h>
#include <unistd.h>

int main() {
    int secret_num = 0x8badf00d;

    char name[64] = {0};
    read(0, name, 64);
    printf("Hello ");
    printf(name);
    printf("! You'll never get my secret!\n");
    return 0;
}
```

Due to how GCC decided to lay out the stack, `secret_num` is actually at a lower address on the stack than `name`, so we only have to go to the 7th "argument" in `printf` to leak the secret:

```
$ ./fmt_string
%7$llx
Hello 8badf00d3ea43eef
! You'll never get my secret!
```