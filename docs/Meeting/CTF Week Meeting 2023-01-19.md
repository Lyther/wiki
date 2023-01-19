# CTF Week Meeting 2023-01-19

Happy New Year in advance to all of you! This is our last weekly meeting before the Spring Festival, and after the Spring Festival, we will start our plans and goals for the new year, so I hope we can still **make progress together** and **build on our success**.

## Work progress tracking

1. COMPASS CTF 2022 - 60%
2. Topic: CTF combined with research - 0%
3. Multi-platform promotion of COMPASS CTF - 20%
4. <u>Training plan during winter break - 33%</u>
5. <u>Member adjustment - 50%</u>
6. New Platform GZCTF - 43%
7. Wiki page content adjustment - 20%
8. CTFtime program: play CTF and sharing - 0%
9. New Member Recruitment - 0%
10. <u>Apply for more ports with ITS on the Detroit server - 33%</u>

## What we discussed this week

1. Member adjustment.
1. Training plan during winter break.
1. Apply for more ports with ITS on the Detroit server.
1. Upcoming events.

### 0x1. Member adjustment

So far I have collected most of the questionnaire results from the members, with a total of **16 results from new members**. Some of them are collected for the training of the last semester, and the other part is the comments and suggestions for the shortcomings of the previous training.

For training participation, <u>50% of the members almost always/always participate</u> in the weekly training program and <u>87.5% of the members would participate</u> in the weekly training program, recommendations regarding training participation I will list later.

Competition participation was unfortunate, with <u>18.8% of members participating in 3-5 competitions</u>, while <u>62.5% of members participated in only 1-2 competitions</u>. I encourage students to participate in more competitions, and I will follow your suggestions to improve the notification and participation format of the competitions.

The day-to-day work of the varsity team includes the maintenance of the wiki page, the updating of the tournament question platform, and the future posting of content to our social media accounts, which is difficult for me to do alone and therefore requires help. Happily, <u>81.3% of the members are willing to assist with this part of the work</u>.

Regarding COMPASS lab, <u>56.2% of the members would like to participate in COMPASS lab research, choose COMPASS colleagues as mentors, or actively prepare to stay in COMPASS as graduate students</u>. COMPASS is a very good environment and platform, and I hope that you would like to choose COMPASS as your future plan.

Unfortunately, after a semester of working together, <u>three members decided to retire</u>, either choosing to continue their studies in other directions or finding that CTF did not fit their future plans. <u>I would also like to wish the members who chose to retire a bright future.</u>

#### Advice

**The training model in question.** There are some very good suggestions under this issue, and I will combine the training content explanation with the topics in future training, starting from the perspective of sharing the topics and introducing what should be explained here.

**About the contest.** I have matched teams according to everyone's intentions, and before the tournament, I would suggest participating through teams, even if you can only make one or two questions, you are contributing to this tournament all the same. In the tournament suggestions, <u>I would make it a little easier to form teams.</u>

In the future, I will also pay attention to everyone's class schedule and CTF time. I will increase the frequency of activities when people are not too busy, and try not to take up too much time during the midterm and final periods.

#### Teams

![HED](../assets/1_hd.png)

![2](../assets/2_hd.png)

![3](../assets/3_hd.png)

![4](../assets/4_hd.png)

I try to make sure the team has no more than **five players** (four + substitutes) so that it can meet the number requirements for most tournaments. For tournaments with a ten-player limit, it is possible to combine two teams for the tournament.

<u>Due to such considerations, some students' team intentions were not met</u>, so if you have any questions about team arrangements or are very interested in joining a particular team, you can also **contact me** and I will rearrange it.

### 0x2. Training plan during winter break

The tournament schedule for the winter break will be synced on my Google calendar and also made public each week in the group for the week. If it is a contest that requires advance registration for team formation, I will synchronize it higher. For the rest of January, here is the schedule of competitions, which students are free to choose their own time to participate in.

| Competition Name              | Link                             | Start Time      | End Time        | Require pre-register |
| ----------------------------- | -------------------------------- | --------------- | --------------- | -------------------- |
| Insomni'hack teaser 2023      | https://insomnihack.ch/contests/ | 2023-1-20 20:00 | 2023-1-22 20:00 | False                |
| KnightCTF 2023                | https://knightctf.com/           | 2023-1-20 23:00 | 2023-1-21 23:00 | False                |
| bi0sCTF 2022                  | https://ctf.bi0s.in/             | 2023-1-21 23:00 | 2023-1-22 23:00 | False                |
| 西湖论剑网络安全技能大赛-初赛 | https://game.gcsis.cn/           | 2023-2-02 00:00 | 2023-2-02 23:59 | **True**             |

For members participating in the competition <u>I suggest posting a link to your team invitation and a link to the competition in the group</u> so that students who are also planning to join the competition can join the team more easily.

In addition, there will be some **basic content recording training** to catch up on **the basics of network security**. These trainings will not take place at a fixed time, and most of them **will be recorded**. If it is an online meeting or a live broadcast, the corresponding recording will also be kept.

The specific content selection I will complete in the near future and will be released on public channels as soon as possible.

### 0x3. Apply for more ports with ITS on the Detroit server

Two weeks ago, I submitted an OA request form to open all ports above 20,000 on the detroit server to accommodate the new GZCTF platform. The new platform assigns ports rather randomly, and the container assignment dependency library it uses does not have the ability to set port ranges, so if you want to limit the ports assigned to 20000-30000, you will need to make some ugly network level changes, which I prefer not to do.

Besides, the originally requested 20,000-30,000 ports are getting stretched and may not meet our service needs in the future, requesting more ports is one solution (another solution is for me to open the docker containers on a public container hosting platform).

After two long weeks of waiting, the OA file was marked as processed, but **the ports were not open**. <u>ITS believes that requesting more than 30,000 ports will still require a new security scan and check, and intends to follow up with me via email (which I have not received so far).</u>

The migration of the GZCTF platform has been affected somewhat, and if the ports are not open, then the dynamic and static container features of GZCTF will not be available off-campus, and I will not be able to run practice rounds on GZCTF (as all topics using containers will not work).

Suffice it to say that <u>the GZCTF migration progress is being blocked by the progress of the ITS application</u>.

I will continue to follow up on the progress of the port application and **hope to finish it as soon as possible**.

### 0x4. Upcoming events

It has been listed above and will not be repeated.

## Wrap-up

The restructuring of new members and team assignments are almost complete, and I have taken some good advice and made adjustments to future plans.

The tournament schedule will make it as easy as possible for students to form teams and hopefully participate in more tournaments. I have listed the recent tournament schedule and the rest of the winter break plans are being designed and will be made public in a few days.

The migration of the GZCTF platform has been delayed by the slow progress of ITS, which I am following up on.
