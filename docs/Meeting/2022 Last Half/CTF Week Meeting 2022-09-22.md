# CTF Week Meeting 2022-09-22

1. Good news.

1. Double good news.

1. ByteCTF register.

1. Offline party time.

1. Training schedule for this week.


## Good news

We got rank 10 in the dfjk CTF final round.

For this score, congratulations to @Frankss, @Monad, @GGA, and me. We won ￥10,000 in this game, and a certification & trophy for our score.

| Rank | Team                    |
| ---- | ----------------------- |
| 1    | Straw Hat               |
| 2    | Redbud                  |
| 3    | D1no                    |
| 4    | 极客信安                |
| 5    | 休闲农庄                |
| 6    | 你干嘛···哈哈···哎哟··· |
| 7    | 小恐龙摸大鱼            |
| 8    | 仔鸡米粉不要香菜        |
| 9    | Nebula                  |
| 10   | **HED**                 |
| 11   | 0x401                   |

## Double good news

In the past wd CTF, we have achieved rank 7 as well.

[Post from WD CTF official](https://mp.weixin.qq.com/s?__biz=Mzg3NTEyOTIyNw==&mid=2247484625&idx=1&sn=797ceaa20bb97b587fb7436623ec32f7&chksm=cec77435f9b0fd231cfde2b63b437c9abc81f2457ffb4a89ddf0a120c7dfe7f43e3620fb9995&mpshare=1&scene=23&srcid=0922IChjwFFWcvq4nPR4ar3s&sharer_sharetime=1663819261222&sharer_shareid=24839d642488f66c87d327e0cf5b7e60#rd)

This is the most famous event which is hosted by Ministry of Public Security. If we won in the semifinal round, we can get the award from them.

| Rank | Team               |
| ---- | ------------------ |
| 1    | Redbud             |
| 2    | 0ops               |
| 3    | 0x401              |
| 4    | Asuri              |
| 5    | 北门辣子鸡         |
| 6    | irusA              |
| 7    | **HED**            |
| 8    | Xp0int             |
| 9    | 来自东方的神秘力量 |
| 10   | H4F                |

Congratulation to @Frankss, @Monad, @GGA. The semifinal round is around 20 days later, offline.

## ByteCTF register

The register due today!!!

https://ctf.bytedance.com/

We need to register on this website, and receive the team invitation.

Now we have 2 teams, all full.

If you are not in either of them, please create a new team, and post the team invitation code in our group.

## Offline party time

Welcome everyone!

Our party has been delayed several times, let's find a time to take a break in Hai Di Lao.

Would it's fine this weekend?

## Training schedule for this week

Our schedule is set to ByteCTF on this Sunday.

But I also wrote some tutorials about the kernel pwn for you. It's a pleasure to share something about pwning.

In the CTF, pwn is the most challenging part of all aspects. Usually, we divide pwn into 3 parts: stack, heap, and kernel.

We already learned about the stack pwn (bof, rop, and rol). However, about the heap and the kernel, we still need to deal with them.

In the kernel pwn, I would introduce several parts:

* Environment setup (qemu).
* Kernel driver design and debug.
* Common steps to solve a kernel pwn.
* Practice with kernel UAF.

After learning about this part, we can try to find some Linux kernel vulnerabilities, just like CVE-2021-3156 or CVE-2021-4034.