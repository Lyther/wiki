# Chaff Bugs: Deterring Attackers by Making Software Buggier

*[Submitted on 2 Aug 2018]*

Authors: [Zhenghao Hu](https://arxiv.org/search/cs?searchtype=author&query=Hu%2C+Z), [Yu Hu](https://arxiv.org/search/cs?searchtype=author&query=Hu%2C+Y), [Brendan Dolan-Gavitt](https://arxiv.org/search/cs?searchtype=author&query=Dolan-Gavitt%2C+B)

Subjects: **Cryptography and Security (cs.CR)**

## Abstract

Sophisticated attackers find bugs in software, evaluate their exploitability, and then create and launch exploits for bugs found to be exploitable. Most efforts to secure software attempt either to eliminate bugs or to add mitigations that make exploitation more difficult. In this paper, we introduce a new defensive technique called chaff bugs, which instead target the bug discovery and exploit creation stages of this process. Rather than eliminating bugs, we instead add large numbers of bugs that are provably (but not obviously) non-exploitable. Attackers who attempt to find and exploit bugs in software will, with high probability, find an intentionally placed non-exploitable bug and waste precious resources in trying to build a working exploit. We develop two strategies for ensuring non-exploitability and use them to automatically add thousands of non-exploitable bugs to real-world software such as nginx and libFLAC; we show that the functionality of the software is not harmed and demonstrate that our bugs look exploitable to current triage tools. We believe that chaff bugs can serve as an effective deterrent against both human attackers and automated Cyber Reasoning Systems (CRSes).

## Related

Chaff CTF: [https://ctftime.org/event/1445](https://ctftime.org/event/1445)

## Download

PDF: [Chaff Bugs Deterring Attackers by Making Software Buggier.pdf](../file/Chaff Bugs Deterring Attackers by Making Software Buggier.pdf)