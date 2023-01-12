# CTF Week Meeting 2022-03-17

1. Competition schedule.
1. CTF Platform dynamic container.
1. Competition management.

## Competition Schedule

2022数字中国创新大赛虎符网络安全赛道

时间：2022-03-19 09:00 ~ 2022-03-20 17:00

https://datacon.qianxin.com/competitions/22/introduction

晋级资格：初赛成绩排名前35的队伍（线上初赛成绩排名前20的高校战队+线上初赛成绩排名前15的行业战队）进入决赛，同一集团单位、高校最多只能入围2支战队，每队不超过4人，及一名领队，决赛前队员可更换，但要求参赛选手需是初赛报名人员，并且必须来自同一集团单位或高校，进入总决赛单位/行业战队需提供半年以上的本单位社保证明，各高校战队需提供加盖所在同一高校公章的在读证明，如发现任何作弊、代打行为，将直接取消比赛资格并进行公告。

Misc: 周翰然、陈梓涵、巫晓、朱嘉楠

Web: 金肇轩、严文谦

Re: 邬一帆、朱弘

PWN: 李照、邬一帆

Crypto: 朱嘉楠、周翰然、严文谦

题目整理 & 同步：邬一帆、李照

## CTFd Dynamic Container

Current solution: https://github.com/frankli0324/ctfd-whale/

The dependency `frp` is vulnerable to SSRF in the history (and very likely now), and have been bypassed several times.

- Should we still deploy on the COMPASS server?

The local deployment is successful and ready to use, but we may have a better alternative.

## Competition Management

For each competition, we would have an administrator. The admin has the following tasks:

* Synchronize the challenges to the Notion.
* Collect the writeups after the competition.

The competitions would use Notion to update.

* Contact @Frankss to be invited.

The competitions would use Discord to chat.

## Note

- [ ] 平台分布部署，容器放在校外
