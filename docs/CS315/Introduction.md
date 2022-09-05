# CS315 CTF Track

| Topics                                                   | Grade |
| :------------------------------------------------------- | ----: |
| Class Participation                                      |    40 |
| Lab 1: Packet Sniffing and Wireshark                     | 60+10 |
| Lab 2: Secure Coding and Buffer Overflows                | 60+10 |
| Lab 3: Secure Coding and Format-String Vulnerability     | 60+10 |
| Lab 4: Scanning, Reconnaissance, and Penetration Testing | 60+10 |
| Lab 5: Reverse Engineering and Obfuscation               | 60+10 |
| Lab 6: IoT Security and Wireless Exploitation            | 60+10 |
| Lab 7: Nailgun Attack                                    | 60+10 |
| Lab 8: Nailgun Defense                                   | 60+10 |
| Lab 9: Dirty COW Attack                                  | 60+10 |
| Lab 10: RSA Public-Key Encryption and Signature          | 60+10 |
| Lab 11: Web Security                                     | 60+10 |
| Lab 12: Return-to-libc & Return Oriented Programming     | 60+10 |
| Attack-Defense CTF                                       |   120 |
| Total                                                    |  1000 |

The lab submission is the same as the Lab track, while CTF has 240 points in total. 120 points of challenges & virtual machine penetration, and 120 points of AWD CTF.

Let's introduce something about the CTF track.

## Overview

CTF majors in the practice part of computer security. CTF (Capture the flag) is one kind of cybersecurity game for hacking and penetration testing. In the real world hacking is illegal and dangerous, while some developers found a new type of game: establish a target box, and try to attack it.

In the CTF track, our mission is to solve some simulation challenges and try to grab the top-secret `flag` from the box. We would have several challenges or virtual machine boxes every week, our goal is to find a vulnerability and use it to achieve some objectives:

1. Run arbitrary code from remote (RCE).
2. Privilege escalation.
3. Reveal secret information (flag).

The ability we need to learn in this track is the real-world hacking methodology. We not only need to solve some CTF challenges that focus on specific vulnerabilities but also a from-zero-to-root hacking using a well-designed target virtual machine. At the end of this semester, we also need to run an Attack-with-Defense competition, in which every player attacks others and fixes their vulnerabilities.

The learning involves:

* Find the correct information from the Internet.
* Utilize exploits and launch a cybersecurity attack in practice.
* How to patch a vulnerability.
* Contribute to real-world cybersecurity, and earn some tips from bug bounty.

Be careful, CS315 is **NOT** easy. We need a lot of computer science knowledge to run a simple attack. Please make sure you have the following requirements:

* Linux usage and compilation from source code.
* Network protocol basics.
* Programming with any language.

## Submission

We would have 3 types of assignments. During the CTF track, we would use a CTF platform as a practice environment and submission check.

Inside the university: http://detroit.sustech.edu.cn/

Through public Internet: http://116.7.234.225/

### CTF Challenge

```
Example:
try to find the plain text of this cipher text.
iodj{brx'uh_zhofrph_wr_wkh_fv315!}
Solution:
Use Caesar cipher, left rotate move every letter, and find the correct plain text.
flag{you're_welcome_to_the_cs315!}
```

The challenge is not a fully functional service. We can focus on the specific part of the real-world vulnerability. The final mission of the CTF challenge is to find a special string that starts with `flag` or `cs315`.

Submit this string to the challenge platform.

However, the assignment we need to submit on the blackboard is not only the flag, we also need to post a `writeup` for this challenge. Simply, a `writeup` is the step to solve the challenge. Just like mathematics questions, write some steps instead of only the result.

### Virtual Machine Box

A virtual machine box is a `.iso` file that contains some websites or services. We first know nothing about the target box. Usually, a virtual machine box contains a real-world-like service, for example, a blog, or an online shopping platform.

We need to retrieve the `root` privilege in this box, each step we would get a `flag` as a step mark.

1. Scan the local IP and find the address of the virtual machine.
2. Information gathering and finding the open services running on the VM.
3. Attack the vulnerable service and get user access to the SSH service.
4. Privilege escalation to get root sid.

We would have 2 virtual machine box hacking in the 4th week and 8th week.

### Attack-with-Defense

The final exam for the CTF track is the AWD game with all CTF track players. Attack-with-Defense requires everyone to have a server, several services are running on the server. All the players need to keep the services running, fix the vulnerabilities in the service, and attack others' servers.

Every method is allowed.

* Left a trojan on others' servers.
* Deploy an EDR on the self server.
* Sniffing the network to capture payload or flag.
* Use honey pot.
* Social engineering or physical attack.

This game would need us to team up. Each team has 4 members, who work together to win the game.

## Grade

The grading system we use would try to eliminate the possibility of the rat race. <u>Attitude is no substitute for competence.</u> The weekly challenges and virtual machines have a maximum score of 10, while the final AWD game doesn't have a maximum score, which means you can get as many as possible points in this game.

For the weekly challenge, we have 3 challenges every week:

* One easy challenge, can be solved using lecture & lab knowledge. - 5 points.
* One medium challenge, can be solved after some searching and reading of extra materials (textbook). - 5 points.
* One hard / very hard challenge, for real hackers and experts. - a bonus for the AWD game.

Let's explain the bonus challenge. The grading system for the AWD game is a log function:

score = (log_1.2(x))^(1+y/100)

x stands for the final points you earn in the AWD, usually, a team has 50,000 initial points, through attacking and defending, you can earn points from others or lose points from others' attacks.

For a tuneful network, without any cybersecurity attacks, every team would get 60 points out of 120 points. However, if a team can earn 1,000,000 points, this team can have 75 points out of 120 points.

Quite a few, right?

But this isn't the final grade, let's talk about the `y` in the exponent. This variable stands for the bonus challenges the team solves in the semester. Each bonus challenge can have 1 bonus points, which gives `y` some bonus. For a 4-member team, if several members have the same bonus challenge solved, the `y` won't be calculated twice (still the same as the bonus points for this challenge).

The maximum `y` value would be around 20.

For example, Frankss solved 6 out of 20 bonus challenges, while Monad solved 7 out of 20 bonus challenges, and they have 3 common solutions to the same challenge. The bonus `y` value would be 10.

If a team has all bonus points 20, they can have 120 points (maximum) in the AWD with only 19,000 AWD points.

Be aware, that this grading system is only for the elimination of the rat race. I hope everyone can learn about cybersecurity, instead of becoming a script kid.

## Extra Bonus

Just like the research track's special rule, if you successfully submitted a paper, the research track would give bonus points. In the CTF track, we can have some similar methods to win the bonus.

* Join a province-level or higher CTF competition and qualified for the final round, and win at least a prize.
* Win a prize from bug bounty.
* Discover or patch some vulnerabilities, get a CVE / CNNVD number (please don't submit useless vulnerabilities, the goal is to contribute to the cybersecurity, not the CVE itself).
* Have participated in the DEF CON final.

* Any other contribution to real-world security.

## Textbook

I would reference this book from the Nu1L team:

从0到1：CTFer成长之路

For the English version, we can reference these wiki:

https://wiki.compass.college/

https://teambi0s.gitlab.io/bi0s-wiki/

## Environment

If you want to use some virtual machine as a penetration environment, instead of your physical computer, there are some great distributions:

* Kali Linux: https://www.kali.org/
* Black Arch Linux: https://blackarch.org/
* Windows 10: https://github.com/makoto56/penetration-suite-toolkit