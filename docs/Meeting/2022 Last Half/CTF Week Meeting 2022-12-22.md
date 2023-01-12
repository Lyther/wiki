# CTF Week Meeting 2022-12-22

1. The status of the recently completed competitions and the plans for the new year
2. the list of winners of COMPASS CTF 2022, and the discussion of prizes
3. the exploration of combining CTF with academic research
4. the proposal and implementation of the COMPASS TEAM on various platforms
5. application for COMPASS TEAM's public email address on campus
6. adjustment of training plan during winter break
7. Registration and ranking adjustment of varsity team members after this semester

## 0x1. The status of the recently completed competitions and the plans for the new year

### Competition Summary

I just participated in the **X-MAS CTF** yesterday, and the topic is very difficult, and I am finishing up the related Writeup and summary.

Some of the more impressive topics are

1. misc/manipulated

Until the last step is normal forensic, however, the last step needs to crack KeePass (a password saving database software), the master obtained in the middle is not directly used for decryption, but needs to attack the encryption mode of KeePass2, by giving the KEY HASH of the file and the uncorrupted MASTER KEY, the .kdbx The encrypted data in the file is extracted and deciphered using its own cryptographic scheme.

2. web/elf

The process of database injection into RCE, the exact implementation I will write in WP.

Finally, it is very sad that I am the only one who participated in many of the recent competitions, probably due to the end of the semester. As a member of the CTF team, I hope you can participate in more competitions.

### Future competitions

**Jule CTF**: As of 12.24.2022 08:00, I have not participated in previous competitions and cannot provide information.

**Damncon 2022**: As of 12.24.2022 23:00, I have not participated in previous tournaments and cannot provide information.

**Spring Cup Winter 2022**: **<u>Registration required</u>**, tournament as of 12.25.2022 18:00, some great topics were done at the Spring tournament, looking forward to this Winter tournament for students who <u>advanced to expert</u> difficulty.

**niteCTF**: As of 12.26.2022 0:00, a very good race, great experience last year for <u>beginners and advanced</u> difficulty.

**The above tournaments are the rest of the year's events, and I am immensely looking forward to having you all join me.**

## 0x2. the list of winners of COMPASS CTF 2022, and the discussion of prizes

In this COMPASS CTF 2022, there were <u>31 participants</u> who completed at least the check-in questions, and the number of prizes expected to be awarded was 15, but in practice I only collected information from the top 15 participants (i.e., there would be **fewer than 15 prizes**).

I collected a total of <u>10 winners</u> who were willing to claim their prizes, so some adjustments will be made to the prize list, which is still a work in progress.

If you have good ideas for this contest, feel free to give suggestions.

Note, this is the list of prizes we started with.

1. 1st place: [¥299] an infiltration system in an SSD that can be used directly for booting.
2. 2nd to 3rd place: [¥88] a USB drive with the infiltration kit installed.
3. Fourth to seventh place：[¥59] Customized T-shirt of COMPASS TEAM.
4. Eighth to fifteenth place：[¥15] COMPASS TEAM stickers.

Therefore, the original prize budget was **¥1,201**, but now <u>the prize budget will be adjusted downward</u> due to the reduction of participants.

## 0x3. the exploration of combining CTF with academic research

This is just a preliminary idea, and I'm still trying to explore this route myself.

Idea from Hongyi Lu: one could take advantage of the fact that vulnerabilities are often reproduced in CTF to examine the CVE vulnerabilities mentioned in the paper, and perhaps improve on those implementations.

For me, it is also very encouraging for people to actively participate in academic research. We often explore new and untouched work in the course of our cybersecurity practice, and these can be part of academic innovation.

I will also invite faculty members in the lab who are dedicated to academic work to give some valuable advice and share.

## 0x4. the proposal and implementation of the COMPASS TEAM on various platforms

COMPASS TEAM in addition to competition work, our work also includes providing science/teaching/guidance for the field of cyber security so that more people are willing to learn cyber security, and we also hope to get more outstanding students to join COMPASS Lab.

As part of COMPASS Lab's promotion and COMPASS TEAM's contribution to cybersecurity, I plan to open COMPASS TEAM accounts on multiple platforms to promote our work.

For different social media, I have planned different focuses, and the following accounts are planned now.

1. **Zhihu**: writeup resolution
2. **CSDN/Bokeyuan**: reproduce wiki content
3. **WeChat public channel**: vulnerability analysis and summary
4. **Kanxue forum**: vulnerability recurrence and research
5. **Anquanke**: technical summary and tutorial
6. **Tik tok**: network security tips
7. **Twitter**: publicity/results sharing
8. **Bilibili**: CTF science and teaching

If you have another social platform to recommend, or have suggestions for guidance on our publicity work, <u>welcome to communicate with me</u>.

## 0x5. application for COMPASS TEAM's public email address on campus

I am communicating with the Information Center and Ms. Qingxia Li to open a COMPASS TEAM email address, which will hopefully facilitate the promotion of the event and lecture/training publicity afterwards.

Since the past, we have been using CRA's public mailbox, which has caused a lot of inconvenience. I hope this work will be convenient for us when it is completed.

## 0x6. adjustment of training plan during winter break

<u>During the winter break, I did not schedule a training program.</u>

However, there will be several race summaries and reviews, and also some catechisms/videos will be recorded and posted, so you can actively participate if you wish.

## 0x7. Registration and ranking adjustment of varsity team members after this semester

After each semester, I recalculate the activity and commitment of the varsity members, hoping that everyone will still maintain their passion for cybersecurity.

I'll be adjusting the roster of active and core members, and perhaps the composition of the team as well. I'll get back to you with the results in the next few days.

<u>I'll post a question paper later, please submit if you are still interested in the CTF (and active in the CTF).</u>
