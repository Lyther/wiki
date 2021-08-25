# myRSA

Category: Cryptography

Source: 祥云杯2021

Author: unknown

Score: 15

## Description

我的第一次密码学导论作业, 参数的生成大家觉得怎样呢？`nc 0.cloud.chals.io 33723`

[ myRSA.zip](https://compass.ctfd.io/files/d64701de3833f5d9cd23ebbe3d32af80/myRSA.zip?token=eyJ1c2VyX2lkIjoxLCJ0ZWFtX2lkIjpudWxsLCJmaWxlX2lkIjo5OX0.YSXzQw.aFXwIEMBQlsR1cJTy-gWh8AVTfg)

## 题目描述

*这题oracle等很久才能生成数（影响了我抢一血的速度）需要耐心等待。*

题目基于RSA，![[公式]](https://www.zhihu.com/equation?tex=N%3Dpq)为1024位数，![[公式]](https://www.zhihu.com/equation?tex=e%3D65537)，加密过程为

![[公式]](https://www.zhihu.com/equation?tex=c%3Dm%5Ee+%5Cbmod+N)

![[公式]](https://www.zhihu.com/equation?tex=x%3Dp%5E2+%28p%2B3q-1%29)

![[公式]](https://www.zhihu.com/equation?tex=y%3Dq%5E2+%28q%2B3p-1%29)

![[公式]](https://www.zhihu.com/equation?tex=z)大概为1024位数

![[公式]](https://www.zhihu.com/equation?tex=c_2+%3D+%28x%2By%29c%2Bz)

题目给出![[公式]](https://www.zhihu.com/equation?tex=N)和flag的密文![[公式]](https://www.zhihu.com/equation?tex=c_2)。并且我们可以输入明文![[公式]](https://www.zhihu.com/equation?tex=m%27)得到对应的密文![[公式]](https://www.zhihu.com/equation?tex=c_2%27)。

## 我的解答

注意到

![[公式]](https://www.zhihu.com/equation?tex=x%2By%3Dp%5E2%28p%2B3q-1%29%2Bq%5E2%28q%2B3p-1%29%3D%28p%2Bq%29%5E3-%28p%2Bq%29%5E2%2B2pq)

也就是

![[公式]](https://www.zhihu.com/equation?tex=x%2By%3D%28p%2Bq%29%5E2%28p%2Bq-1%29%2B2N)

然后![[公式]](https://www.zhihu.com/equation?tex=c_2+%3D+%28x%2By%29c%2Bz)可以看成是![[公式]](https://www.zhihu.com/equation?tex=c_2)对![[公式]](https://www.zhihu.com/equation?tex=c)的带余除法。我们可以利用第一步的![[公式]](https://www.zhihu.com/equation?tex=m%27)对应的![[公式]](https://www.zhihu.com/equation?tex=c_2%27)（此时我们可以自己计算出![[公式]](https://www.zhihu.com/equation?tex=c%27%3Dm%27%5Ee+%5Cbmod+N)来）可以直接得到![[公式]](https://www.zhihu.com/equation?tex=x%2By)的值。然后对![[公式]](https://www.zhihu.com/equation?tex=x%2By-2N)开三次方可以开出![[公式]](https://www.zhihu.com/equation?tex=p%2Bq-1)来。

然后就可以结合![[公式]](https://www.zhihu.com/equation?tex=N%3Dpq)，用`z3-solver`解出![[公式]](https://www.zhihu.com/equation?tex=p)和![[公式]](https://www.zhihu.com/equation?tex=q)。

之后就可以计算出![[公式]](https://www.zhihu.com/equation?tex=x)和![[公式]](https://www.zhihu.com/equation?tex=y)的值，并且利用![[公式]](https://www.zhihu.com/equation?tex=c_2)除以![[公式]](https://www.zhihu.com/equation?tex=x%2By)得到RSA的密文![[公式]](https://www.zhihu.com/equation?tex=c)，然后解RSA即可。

过掉oracle的proof of work检测，然后等几分钟，拿到![[公式]](https://www.zhihu.com/equation?tex=N)和![[公式]](https://www.zhihu.com/equation?tex=c)，然后随便输入一个`1`得到密文![[公式]](https://www.zhihu.com/equation?tex=c_2%27)。将得到的值输入代码：

```python
import gmpy2
from z3 import *
from Crypto.Util.number import *

n = 121642065448176156473897179092419728921875357974980389083860655277565704825649889226444419608980002630759091596085557548487575346914669740739314941122290996740304245650872046561895900796258456608793055028467475091633433839705791878132565383650206725088639081180463351423103722622744738467167869749662990688979

cc = 1136361046033913612036332714569670427841256258685140344055068620567475033294018028371032984703266206522526501010193123738345243273176762739282234315795608086725508770575402683003031958708516685141549840548134463272675351840929630389108825535204457117771682170437521557495770971608166831028637021920921360209937746104425491678161944802864369442195541546254091075147348470471884402144293370533562623258123204821582501280968271504384904817447094261612944693686431804933040510678517012219972815762511119200409624840705484711608894758448331870766284821627574717762202817452703132562199236232290523206855898302762507824719214766649522917767889370878378892167034276829407953963424463895887129146755081368470643425950316309913064297742492397168974520285387936917948771030039018332

cf = 295318431540053515087200928667285571195873544800963850029171139457738083432353682348226869156528183688490148373759627896871330766900837785451589779523111914618842905371837548861785389600883467087532763343406914524095383977741052854917948885361134719361023858033122670278053750085303927034983764865067526075420830992291379676788114928196956733017730193604813935484846679831060231258082875209851746699146625709301590969332851864108352895567376700175971571387738401144667542370193792481515722502753499780996972280714436836825211823165098486303895898784162737206171512239610585374041011016685047322413395385902117183922652085520924218305511771316307760747269759565922379004659918873467812356832776152950611990185909516951703495925411981576965707961331962771430522666692227338

m = 49
e = 0x10001
c = pow(m, e, n)
cc = cc // c
my = cc - 4 * n

my1, ok = gmpy2.iroot(my, 3)

p, q = Ints('p q')
sol = Solver()
ppq = int(ppq)
sol.add(p + q == ppq)
sol.add(p * q == n)
if (sol.check() == sat):
    m = sol.model()
    p = m[p].as_long()
    q = m[q].as_long()
    x = p**2 * (p + 3*q - 1 ) + q**2 * (q + 3*p - 1) 
    y = 2*p*q + p + q
    cf = cf // (x + y)
    mf = pow(cf, inverse(e, (p-1)*(q-1)), n)
    print(long_to_bytes(mf))
else:
    print('GG simida')
```

## Flag

```text
flag{ed649951-9ce9-46e0-a42b-d0ba588e43e1}
```

## Reference

Writeup from [https://zhuanlan.zhihu.com/p/402690414](https://zhuanlan.zhihu.com/p/402690414)

