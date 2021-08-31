# more_calc

Category: Cryptography

Source: 祥云杯2020

Author: unknown

Score: 25

## Description

maybe u need more cpu

## Solution

```python
import gmpy2
from Crypto.Util.number import *


flag = b"flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}"


p = getStrongPrime(2048)
for i in range(1, (p+1)//2):
    s += pow(i, p-2, p)
s = s % p
q = gmpy2.next_prime(s)
n = p*q
e = 0x10001
c = pow(bytes_to_long(flag), e, n)
print(p)
print(c)
#27405107041753266489145388621858169511872996622765267064868542117269875531364939896671662734188734825462948115530667205007939029215517180761866791579330410449202307248373229224662232822180397215721163369151115019770596528704719472424551024516928606584975793350814943997731939996459959720826025110179216477709373849945411483731524831284895024319654509286305913312306154387754998813276562173335189450448233216133842189148761197948559529960144453513191372254902031168755165124218783504740834442379363311489108732216051566953498279198537794620521800773917228002402970358087033504897205021881295154046656335865303621793069
#35055918683748883282174784323651813560520737603185800227424500428762264933021511381871995418539707283801414497303232960090541986190867832897131815320508500774326925395739528242032566313216102210036548100374594081897428098804503420454038574457280610255242042832626554192534670284369336699175346822030007088865173250252079700270724860427575514471342164997149244044205247072315311115645755855836214700200464613652201134426101746190195358346246762242881016710707928119020973125199597600335220176686188732073999025860155060600538887296782517962617671450347555788381054344555539001456268680189452831160062315698482986474322296387716709989292671747978922668181058489406663507675599642320338049377613048817085979874567772781052867215035033348050642450667612710852648837001109914769887507004392552421783737965416800917979813137835262317794775319294801257483177741372991005066875900770459644762548438474388076655842822437141772648037236281057239552272508379892613346840960049192531743799845858272389712078645821963027561694961956409973354276629777068204456160534409039477757097372521171307620184694243888389707840806777932547158990704118642378158004690358831695861544319681913385236756504946707671037639508589887549565323717819837942112908652
```

想求q，得先求s，又因为s是 pow(i, p-2, p) 的累和( i 从1到 (p+1)//2 )，可以费马小定理求p 和 (p+1)//2 -1 求逆元

```python
# -*- coding: utf-8 -*-
# @Project: Hello Python!
# @File   : exp
# @Author : Tr0jAn <Tr0jAn@birkenwald.cn>
# @Date   : 2020-11-22
import gmpy2
from Crypto.Util.number import long_to_bytes
p = 27405107041753266489145388621858169511872996622765267064868542117269875531364939896671662734188734825462948115530667205007939029215517180761866791579330410449202307248373229224662232822180397215721163369151115019770596528704719472424551024516928606584975793350814943997731939996459959720826025110179216477709373849945411483731524831284895024319654509286305913312306154387754998813276562173335189450448233216133842189148761197948559529960144453513191372254902031168755165124218783504740834442379363311489108732216051566953498279198537794620521800773917228002402970358087033504897205021881295154046656335865303621793069
s = gmpy2.invert(p, (p+1)//2-1)
s = s % p
q = gmpy2.next_prime(s)
e = 0x10001
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
n = p*q
c = 350559186837488832821747843236518135605207376031858002274245004287622649330215113818719954185397072838014144973032329600905419861908678328971318153205085007743269253957395282420325663132161022100365481003745940818974280988045034204540385744572806102552420428326265541925346702843693366991753468220300070888651732502520797002707248604275755144713421649971492440442052470723153111156457558558362147002004646136522011344261017461901953583462467622428810167107079281190209731251995976003352201766861887320739990258601550606005388872967825179626176714503475557883810543445555390014562686801894528311600623156984829864743222963877167099892926717479789226681810584894066635076755996423203380493776130488170859798745677727810528672150350333480506424506676127108526488370011099147698875070043925524217837379654168009179798131378352623177947753192948012574831777413729910050668759007704596447625484384743880766558428224371417726480372362810572395522725083798926133468409600491925317437998458582723897120786458219630275616949619564099733542766297770682044561605344090394777570973725211713076201846942438883897078408067779325471589907041186423781580046903588316958615443196819133852367565049467076710376395085898875495653237178198379421129086523
m = pow(c, d, n)
print(long_to_bytes(m))
```

## Flag

flag{3d7f8da9-ee79-43c0-8535-6af524236ca1}

## Reference

Writeup from [https://mp.weixin.qq.com/s/0b9nQRxkbu7mDPji_Y8Ghw](https://mp.weixin.qq.com/s/0b9nQRxkbu7mDPji_Y8Ghw)
