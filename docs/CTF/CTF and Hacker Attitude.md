# CTF Introduction and the Hacker Attitude

> https://ctf101.org/
>
> http://www.catb.org/~esr/faqs/hacker-howto.html
>
> https://ctf-wiki.org/

## CTF Introduction

Capture The Flags, or CTFs, is a kind of computer security competition.

Teams of competitors (or just individuals) are pitted against each other in a test of computer security skills.

Very often CTFs are the beginning of one's cyber security career due to their team-building nature and competitive aspect. In addition, there isn't a lot of commitment required beyond a weekend.

### Origin of CTF

CTF's predecessor is a traditional networking technology competition between hackers, which originated at the 4th DEFCON in 1996.

### Early CTF Competitions

The first CTF competitions (1996 - 2001) had no clear rules and no professionally built competition platform and environment. It was up to the teams to prepare their own targets (prepare and defend their own targets, and try to break each other's targets). The organizers are mostly just non-professional volunteers who accept requests for manual scoring from the participating teams.

The lack of automated back-end systems and judges' technical competence, scoring delays and errors, as well as unreliable networks and improper configurations, led to a great deal of controversy and dissatisfaction.

### The "Modern" CTF Competition

A professional team undertakes the competition platform, proposition, event organization, and automated point system. Teams are required to submit applications and are selected by the DEFCON conference organizers.

The following features stand out for the three years of DEFCON CTF competitions organized by LegitBS.

The competition focuses on core competencies in underlying computer and system security, and web vulnerability techniques are completely ignored.
The competition environment tends to be a multi-CPU instruction architecture set, multi-operating system, and multi-programming language.
Zero-sum" scoring rules are used.
The team's comprehensive ability test: reverse analysis, vulnerability mining, vulnerability exploitation, vulnerability patching and reinforcement, network traffic analysis, system security operation and maintenance, and security programming debugging.

### CTF Competition Types

Jeopardy is commonly used in online selection competitions. In Jeopardy CTF, teams can participate via the Internet or a live network, where they solve technical challenges in cybersecurity by interacting with the online environment or analyzing files offline to earn points, similar to ACM programming competitions and informatics Olympiads, and are ranked based on total points and time.

The different problem-solving problem-solving modes will generally set the first blood, and second blood, third blood, that is, the first three teams to complete the problem will get extra points, so this is not only the first team to solve the problem to encourage the value of the team, but also an indirect reflection of the team's ability.

Of course there is also a popular scoring rule that sets the initial score for each question and then gradually reduces the score of the question according to the number of teams that have successfully answered the question, meaning that the more people answer the question, the lower the score of the question will be. Eventually it will drop to a guaranteed score and then stop dropping.

The main types of questions include **Web** network attack and defense, **RE** reverse engineering, **Pwn** binary exploit, **Crypto** cryptographic attacks, **Mobile** mobile security, and **Misc** security miscellaneous six categories.

### CTF Contest Contents

Since the CTF has a wide range of questions, there are no clear boundaries as to what will be tested. However, as far as the current competition questions are concerned, they are mainly classified according to the common Web network attack and defense, RE reverse engineering, Pwn binary vulnerability exploitation, Crypto cryptography attack, Mobile security, and Misc security.

#### Web - Web Attack and Defense

Mainly introduces the common vulnerabilities in Web security, such as SQL injection, XSS, CSRF, file inclusion, file upload, code audit, PHP weak types, etc., common questions and solutions in Web security, and provides some common tools.

#### Reverse Engineering - Reverse Engineering

Mainly introduces the common question types, tools platform, and solution ideas in Reverse Engineering, and the advanced part introduces the common software protection, decompiling, anti-debugging, shelling, and deshelling techniques in Reverse Engineering.

#### Pwn - binary vulnerability exploitation

The Pwn topic mainly examines the discovery and exploitation of binary vulnerabilities, which requires a certain understanding of the underlying computer operating system. PWN topics are mainly found on the Linux platform in the CTF competition.

#### Crypto - Cryptographic Attacks

Classical cryptography is interesting and diverse, while modern cryptography is highly secure and requires high algorithmic understanding.

#### Mobile - Mobile Security

Mainly introduces the common tools and main problem types in Android inversion. Android inversion often requires certain knowledge of Android development. iOS inversion topics are less frequent in CTF competitions, so not too much introduction is made.

#### Misc - Security Miscellaneous

The topic "Online Ghost: The Autobiography of Mitnick, the World's Number One Hacker" translated by Zhuge Jianwei, and some typical MISC topics are used as entry points, mainly including information gathering, coding analysis, forensic analysis, steganography analysis, etc.

## How To Become A Hacker

### What Is a Hacker?

The [Jargon File](http://www.catb.org/jargon) contains a bunch of definitions of the term ‘hacker’, most having to do with technical adeptness and a delight in solving problems and overcoming limits. If you want to know how to *become* a hacker, though, only two are relevant.

There is a community, a shared culture, of expert programmers and networking wizards that traces its history back through decades to the first time-sharing minicomputers and the earliest ARPAnet experiments. The members of this culture originated the term ‘hacker’. Hackers built the Internet. Hackers made the Unix operating system what it is today. Hackers make the World Wide Web work. If you are part of this culture, if you have contributed to it and other people in it know who you are and call you a hacker, you're a hacker.

The hacker mindset is not confined to this software-hacker culture. Some people apply the hacker attitude to other things, like electronics or music — actually, you can find it at the highest levels of any science or art. Software hackers recognize these kindred spirits elsewhere and may call them ‘hackers’ too — and some claim that the hacker nature is independent of the particular medium the hacker works in. But in the rest of this document, we will focus on the skills and attitudes of software hackers, and the traditions of the shared culture that originated the term ‘hacker’.

There is another group of people who loudly call themselves hackers, but aren't. These are people (mainly adolescent males) who get a kick out of breaking into computers and phreaking the phone system. Real hackers call these people ‘crackers’ and want nothing to do with them. Real hackers mostly think crackers are lazy, irresponsible, and not very bright, and object that being able to break security doesn't make you a hacker any more than being able to hotwire cars makes you an automotive engineer. Unfortunately, many journalists and writers have been fooled into using the word ‘hacker’ to describe crackers; this irritates real hackers no end.

The basic difference is this: hackers build things, and crackers break them.

If you want to be a hacker, keep reading. If you want to be a cracker, go read the [alt.2600](news:alt.2600) newsgroup and get ready to do five to ten in the slammer after finding out you aren't as smart as you think you are. And that's all I'm going to say about crackers.

## The Hacker Attitude

- 1. The world is full of fascinating problems waiting to be solved.
- 2. No problem should ever have to be solved twice.
- 3. Boredom and drudgery are evil.
- 4. Freedom is good.
- 5. Attitude is no substitute for competence.

Hackers solve problems and build things, and they believe in freedom and voluntary mutual help. To be accepted as a hacker, you have to behave as though you have this kind of attitude yourself. And to behave as though you have the attitude, you have to really believe the attitude.

But if you think of cultivating hacker attitudes as just a way to gain acceptance in the culture, you'll miss the point. Becoming the kind of person who believes these things are important for *you* — for helping you learn and keeping you motivated. As with all creative arts, the most effective way to become a master is to imitate the mindset of masters — not just intellectually but emotionally as well.

Or, as the following modern Zen poem has it:


  To follow the path:
  look to the master,
  follow the master,
  walk with the master,
  see through the master,
  become the master.

So, if you want to be a hacker, repeat the following things until you believe them:

### 1. The world is full of fascinating problems waiting to be solved.

Being a hacker is lots of fun, but it's a kind of fun that takes lots of effort. The effort takes motivation. Successful athletes get their motivation from a kind of physical delight in making their bodies perform, and in pushing themselves past their physical limits. Similarly, to be a hacker you have to get a basic thrill from solving problems, sharpening your skills, and exercising your intelligence.

If you aren't the kind of person that feels this way naturally, you'll need to become one to make it as a hacker. Otherwise, you'll find your hacking energy is sapped by distractions like sex, money, and social approval.

(You also have to develop a kind of faith in your own learning capacity — a belief that even though you may not know all of what you need to solve a problem, if you tackle just a piece of it and learn from that, you'll learn enough to solve the next piece — and so on, until you're done.)

### 2. No problem should ever have to be solved twice.

Creative brains are a valuable, limited resource. They shouldn't be wasted on re-inventing the wheel when there are so many fascinating new problems waiting out there.

To behave like a hacker, you have to believe that the thinking time of other hackers is precious — so much so that it's almost a moral duty for you to share information, solve problems and then give the solutions away just so other hackers can solve *new* problems instead of having to perpetually re-address old ones.

Note, however, that "No problem should ever have to be solved twice." does not imply that you have to consider all existing solutions sacred, or that there is only one right solution to any given problem. Often, we learn a lot about the problem that we didn't know before by studying the first cut at a solution. It's OK, and often necessary, to decide that we can do better. What's not OK is artificial technical, legal, or institutional barriers (like closed-source code) that prevent a good solution from being re-used and *force* people to re-invent wheels.

(You don't have to believe that you're obligated to give *all* your creative product away, though the hackers that do are the ones that get the most respect from other hackers. It's consistent with hacker values to sell enough of it to keep you in food and rent and computers. It's fine to use your hacking skills to support a family or even get rich, as long as you don't forget your loyalty to your art and your fellow hackers while doing it.)

### 3. Boredom and drudgery are evil.

Hackers (and creative people in general) should never be bored or have to drudge at stupid repetitive work because when this happens it means they aren't doing what only they can do — solve new problems. This wastefulness hurts everybody. Therefore boredom and drudgery are not just unpleasant but evil.

To behave like a hacker, you have to believe this enough to want to automate away the boring bits as much as possible, not just for yourself but for everybody else (especially other hackers).

(There is one apparent exception to this. Hackers will sometimes do things that may seem repetitive or boring to an observer as a mind-clearing exercise, to acquire a skill or have some particular kind of experience you can't have otherwise. But this is by choice — nobody who can think should ever be forced into a situation that bores them.)

### 4. Freedom is good.

Hackers are naturally anti-authoritarian. Anyone who can give you orders can stop you from solving whatever problem you're being fascinated by — and, given the way authoritarian minds work, will generally find some appallingly stupid reason to do so. So the authoritarian attitude has to be fought wherever you find it, lest it smothers you and other hackers.

(This isn't the same as fighting all authority. Children need to be guided and criminals restrained. A hacker may agree to accept some kind of authority to get something he wants more than the time he spends following orders. But that's a limited, conscious bargain; the kind of personal surrender authoritarians want is not on offer.)

Authoritarians thrive on censorship and secrecy. And they distrust voluntary cooperation and information-sharing — they only like the ‘cooperation’ that they control. So to behave like a hacker, you have to develop an instinctive hostility to censorship, secrecy, and the use of force or deception to compel responsible adults. And you have to be willing to act on that belief.

### 5. Attitude is no substitute for competence.

To be a hacker, you have to develop some of these attitudes. But copping an attitude alone won't make you a hacker, any more than it will make you a champion athlete or a rock star. Becoming a hacker will take intelligence, practice, dedication, and hard work.

Therefore, you have to learn to distrust attitudes and respect competence of every kind. Hackers won't let posers waste their time, but they worship competence — especially competence at hacking, but competence at anything is valued. Competence at demanding skills that few can master is especially good, and competence at demanding skills that involve mental acuteness, craft, and concentration is best.

If you revere competence, you'll enjoy developing it in yourself — the hard work and dedication will become a kind of intense play rather than drudgery. That attitude is vital to becoming a hacker.