# CTF Week Meeting 2022-06-03

1. 2nd Guangdong CTF Final.
1. AWD introduction and the toolkit.
1. Summer schedule.
1. The upcoming training and the competitions.

## 2nd Guangdong CTF Final

The competition score of HED is 9th place in the CTF and 80% in the knowledge challenge.

HED: 8th rank and qualified for the final round.

If you are very close to the final, don't be upset. Try harder and your studies would be paid back.

| Team         | Score to final |
| ------------ | -------------- |
| MFGI         | 0.38           |
| W3r3wo1fki11 | 10.14          |
| 猫猫划水队   | 11.22          |

You are very talented. 10 points can be a 400 points challenge, keeping learning and you can win very soon.

## AWD

AWD, attack with defense.

https://youtu.be/RkaLyji9pNs

### The Gameserver

It is provided by the organizers and runs throughout the competition, starting when the network is opened. It periodically stores flags on your Vulnbox using the functionality in the provided services. It then later retrieves these flags, again using existing functionality. The Gameserver **does not** run exploits! It simply uses the service as intended.

> Now, why can't the other teams then simply do what the Gameserver does?

The Gameserver has more information. Every service is either designed to allow the Gameserver to store a specific token for each flag or generates one and returns it to the Gameserver.

The Gameserver uses this token to check periodically that the flag is still there. Whether or not it gets the stored flag using that token, determines your SLA (Service Level Agreement). You mustn't remove or break any legitimate functionality.

Some services can have a vulnerability that directly leaks the flag, which will let you retrieve the flag easily. For others, it will require more effort.

### Your Vulnbox

The Vulnbox is your running instance of the virtual machine image given to you by the organizers. It contains and runs all the services of the competition and should be reachable at all times. The Gameserver stores its flags here and uses the communication with this machine to decide if your services are working as intended or not. This machine is accessible to everyone on the network, and is the target for all the exploits from other teams.

Protecting the flags on this machine is what determines your defense points!

You normally have one hour from getting the decryption password of your Vulnbox until the network between teams is opened and everyone can attack each other. Use this time to get the VM running, then start analyzing what's running on it. It has happened that services with vulnerabilities that are easy to find have been exploited as soon as the actual competition starts.

For learning how to host the Vulnbox, have a look at [Basic Vulnbox Hosting](https://2021.faustctf.net/information/basic-vulnbox-hosting/).

### The other teams

All the other registered teams are connected to the same VPN as you. Their Vulnboxes have known IP addresses, all other machines are off-limits! The other teams will run exploits from their own machines, but the VPN infrastructure will use NAT to obfuscate whether a packet came from the Gameserver or another team.

Successfully stealing and submitting flags from the Vulnbox of other teams determines your attack score!

If you have played jeopardy CTFs before, you already know flag submission. In this game, however, you'll have to run your exploits periodically, as new flags get stored by the Gameserver every few minutes. So you probably want to script exploits and submit Flags automatically and you don't spend all your time manually exploiting everyone.

### Training and toolkit about AWD

We can hold an AWD training and competition this weekend, if you are interested to.



## Note

- [ ] 暑期计划相关的文档整理与情报收集

