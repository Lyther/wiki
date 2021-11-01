# 100 Forensics / Wi Will H4CK YOU!!

**Description**

> Wifi Security Standards have been increased a lot in recent times.
>
> But are they secure enough??? Get the password for our Wifi Network "encryptCTF"
>
> Submit flag as encryptCTF{</password/>} [captured.cap](https://drive.google.com/open?id=1IqDZec42qoeTxgltKwie_8XszPX3OGBu)
>
> ```
> Author:@mostwanted002
> ```

**Files provided**

- [encryptCTFWPA.cap](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-04-02-encryptCTF/files/encryptCTFWPA.cap)

**Solution**

This challenge is similar to [It's a WrEP](https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-04-02-encryptCTF/README.md#50-forensics--its-a-wrep) challenge. The only difference is that it is using the WPA protocol instead of the WEP protocol.

Using `aircrack-ng` again and waiting for a long time, give us the password.

```
$ aircrack-ng -a 2 -w rockyou.txt encryptCTFWPA.cap
```

We pass in a wordlist (rockyou.txt in this case) and picking the network to crack and waiting for quite some time, it outputs the password `ThanckYou`.

```
encryptCTF{ThanckYou}
```

# 恶臭的数据包

## 题目

野兽前辈想玩游戏，但是hacker妨碍了他连上无线网，前辈发出了无奈的吼声。

题目存档：[恶臭的数据包.7z](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/problems/恶臭的数据包.7z)

## 解决方案

解压得到一个cap流量包，Wireshark打开看看统计信息：

![恶臭的数据包_1.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_1.png)

一个无线流量包，信息都被加密了。来看看有没有握手包：

![恶臭的数据包_2.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_2.png)

这个时候可以来尝试爆破了。Kali Linux，启动：

`aircrack-ng -w ./rockyou.txt ./cacosmia.cap `

还是那个经典的字典。

![恶臭的数据包_3.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_3.png)

很快就爆出来了，无线密码是`12345678`。这个时候可以来解密了：

![恶臭的数据包_4.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_4.png)

Protocols -> IEEE 802.11 -> Decryption keys直达：

![恶臭的数据包_5.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_5.png)

![恶臭的数据包_6.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_6.png)

保存退出，此时应该能看到已经解密了。开始追踪流，先过滤一下再开始：

![恶臭的数据包_7.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_7.png)

![恶臭的数据包_8.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_8.png)

翻到后面就发现有些上传图片的流量。熟悉的PNG文件头：

![恶臭的数据包_9.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_9.png)

还有让人激动的PK文件头和flag.txt:

![恶臭的数据包_10.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_10.png)

先提取出来再说：

![恶臭的数据包_11.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_11.png)

这样导出有HTTP头部信息，用010 Editor去掉即可得到一个图种，可以继续编辑把图和 ~~种~~ 压缩包拆开。也可以用binwalk或者foremost之类的工具分离出来。图用Stegsolve看了看似乎没有什么信息，压缩包被加密了：

![恶臭的数据包_12.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_12.png)

不是个伪加密，回到流量包里找线索。发现Cookie有个JWT，尝试解开：

![恶臭的数据包_13.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_13.png)

提示密码是被ping过的一个站点。回到流量包中尝试过滤：

![恶臭的数据包_14.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_14.png)

没有发现。不过ping一个站点通常会先进行DNS解析：

![恶臭的数据包_15.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_15.png)

发现最后一次解析有点可疑，返回了环回地址，如果ping环回的话，确实是会抓不到包的。尝试用`26rsfb.dnslog.cn`解压：

![恶臭的数据包_16.png](https://szu17dmy.github.io/site/ctf_writeup/redhat_2019/img/%E6%81%B6%E8%87%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85_16.png)

`flag{f14376d0-793e-4e20-9eab-af23f3fdc158}`

# **wifi**

vol内存取证，直接找zip，找到个奇怪的

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-41.png)

导出，发现需要密码，

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-42.png)

老考点了

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-43.png)

花括号以内加花括号是密码，解压后获得xml，xml获得密码

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-44.png)

对加密的客户端流量进行解密，即可

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-45.png)

随后进入流量分析环节。

首先分析服务器流量，直接看http

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-46-1024x49.png)

这是哥斯拉shell的初始化

我们解密得到加密函数和key

```
function encode($D,$K){

    for($i=0;$i<strlen($D);$i++) {

        $c = $K[$i+1&15];

        $D[$i] = $D[$i]^$c;

    }

    return $D;

}

$pass='key';

$payloadName='payload';

$key='3c6e0b8a9c15224a';
```

加密函数也是解密函数

分析客户端流量的回显

![img](http://www.snowywar.top/wp-content/uploads/2021/09/image-47.png)

去掉前面的16位和后面的16位 得到

fL1tMGI4YTljMn75e3jOBS5/V31Qd1NxKQMCe3h4KwFQfVAEVworCi0FfgB+BlWZhjRlQuTIIB5jMTU=

哥斯拉输出结果是会将结果压缩然后加密

```
 $result=gzencode($result,6);

 echo base64_encode(encode(@run($data),$key));
```

然后进行解密

```
function encode($D,$K){

    for($i=0;$i<strlen($D);$i++) {

        $c = $K[$i+1&15];

        $D[$i] = $D[$i]^$c;

    }

    return $D;

}

$a= 'fL1tMGI4YTljMn75e3jOBS5/V31Qd1NxKQMCe3h4KwFQfVAEVworCi0FfgB+BlWZhjRlQuTIIB5jMTU=';

echo gzdecode(encode(base64_decode($a),'3c6e0b8a9c15224a'));
```

得到flag

flag{5db5b7b0bb74babb66e1522f3a6b1b12}
