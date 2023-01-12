# CTF Week Meeting 2022-07-14

1. Training schedule.
1. CTFd-whale environment and challenge docker.
1. Competition register notification.

## Training Schedule

Summer schedule have already finished the first two weeks. From the last week, we have 53 registered members.

| Date   | Morning | Afternoon |
| ------ | ------- | --------- |
| Week 2 | 19      | 22        |
| Week 3 | 14      | 21        |

In the past few weeks we have some interesting sharing materials. Including things I haven't mentioned in the tutorial.

In this weekend, we would look forward to the sharing from:

* 冯泉弼: HTTP Request Smuggling
* 吴亓: CTF 101 Web Tutorial
* 唐骞: SQL Injection

Hope everyone enjoys summer schedule.

## CTFd-whale

http://detroit.sustech.edu.cn is now applying for the public Internet access. The ports are 80/443, 28000-30000.

https://hub.docker.com/search?q=compassctf contains the docker image for CTFd-whale containers. I'm still working on the image construction. The old https://compass.ctfd.io/ would be configured to the new location after the setup.

Containers I have done:

* php_inclusion
* php4fun6
* web11
* 003fileupload
* php_audit
* callme
* php4fun9
* php4fun2
* php4fun1
* php4fun4
* cbc
* web12
* badchars
* php4fun5
* web9

Containers under construction:

* sanity_check
* web_sign
* dove_server
* tricky_php
* bbs
* wish_server
* ret2win
* split
* write4
* fluff
* pivot
* exec_1

Meanwhile, I'm going to write a quick start for CTFd-whale docker image construction, and we can make some new nice challenges.

## Competition Notification

### 网鼎杯

The ITS has called me to sign up this competition, and we would like to attend this event.

https://www.wangdingcup.com/

Register due to July, 27th. Please send me those information:

1. Your name.
2. Your phone number.
3. Your ID number.
4. Your department.
5. Your email.

The information can be sent through WeChat directly, otherwise by using my PGP public key to encrypt.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v2.0.76
Comment: https://keybase.io/crypto

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
=s/qg
-----END PGP PUBLIC KEY BLOCK-----
```

I won't store your information. So, I might ask you for those information again for different events.

### ENOWARS 6

https://6.enowars.com/

星期六, 16 七月 2022, 21:00 CST — 星期日, 17 七月 2022, 05:00 CST

An A/D CTF, I've signed up for team C0MP4SS.

## Note

- [ ] 周末训练材料更新+基础内容补充
- [ ] 题目容器打包
- [ ] AWD武器库搭建

