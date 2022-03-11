# CTF Week Meeting 2022-03-03

1. Review of the recent competitions.
1. COMPASS CTF platform has moved back to VPS.
1. Wiki page update and maintenance.
1. Competition of the weekend.

## Competition Review

### CODEGATE 2022

We have achieved rank 29.

![CODEGATE 2022](../assets/codegate_1.png)

The rank is in the top tier 2 list. The top 20 teams are very famous `organizers`, `r3kpig`, `DiceGang`, `Oops`, and `perfect blue`. Our rank is along with `Super Guesser`. In the meanwhile, we have won `Redbud` for continuous 3 times.

Still, we have some areas to improve. First of all, all of our scores are from the Web category. PWN is still an area we should improve.

The Rev and Crypto of the codegate are very difficult.

## CTFshow

Congratulations to Frankss!

Looking forward to your next rank 1 in CTF!

## CTF Platform

In the past very long time, we use CTFd online collocation system to deploy our platform. The CTFd online service is limited now.

The black box of CTFd doesn't offer us direct interaction with the source code and the plugins. In order to make further improvements, we are going to switch back to the local VPS deployment.

We have 2 plans:

A. **use my personal VPS server.** The VPS is in Hong Kong with 8 CPU cores and 16 GB of memory. The access of VPS is open to the public network. In order to deploy in my VPS, we need to assign an SSL certification and allocate a domain name service to the docker image.

B. **use COMPASS server.** The COMPASS server is very high performance. To use the COMPASS's Detroit server, we can directly use the `compass.sustech.edu.cn` domain name. But the access is limited to the campus. If we want to let users outside the SUSTech access, we need to deploy a jump service.

We need to assign the maintenance of the CTF platform to our members. If you are interested, please let me know. The work of the maintenance involves:

1. make sure the platform is online and the docker image is working properly.
2. make sure all the challenge container is online.
3. analysis of the network traffic logs to prevent attackers.

## Wiki

The Wiki page is critical for our public information. We have updated our Wiki page several times.

https://wiki.compass.college/member/

On the members' page, we have all of our members' cards. Currently, all the members' information is using our Wechat profile and the area is set to `ALL`.

Obviously, we need to update this page. Please send me your area.

## Competition

https://mp.weixin.qq.com/s?__biz=Mzg5NTc0ODE4Ng==&mid=2247483653&idx=1&sn=8f2f74843dd5eff531be187823d9fc90&chksm=c00ad030f77d5926157929aee64fab31ead3b2b727777633a567a1dc5a579dd3f8a61d603435&mpshare=1&scene=23&srcid=0302kUF13DdLm2lLcV7DCIqL&sharer_sharetime=1646213771898&sharer_shareid=612cf76d62ce2a19afbb97fe3bdd60a8#rd

https://www.qianxin.com/DCICHF/2022

## Note

- [ ] 护网行动申请相关，进行联络。
- [x] Wiki的联络方式添加，周四会议的link链接。
- [x] Wiki的meeting notes放在更显眼的地方。
- [ ] 对外宣传的工作。
