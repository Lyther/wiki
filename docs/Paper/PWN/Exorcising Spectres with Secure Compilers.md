# Exorcising Spectres with Secure Compilers

*[Submitted on 18 Oct 2019 (*[v1](https://arxiv.org/abs/1910.08607v1)*), last revised 10 Sep 2021 (this version, v4)]*

Authors: [Marco Patrignani](https://arxiv.org/search/cs?searchtype=author&query=Patrignani%2C+M), [Marco Guarnieri](https://arxiv.org/search/cs?searchtype=author&query=Guarnieri%2C+M)

Subjects: **Programming Languages (cs.PL)**

## Abstract

Attackers can access sensitive information of programs by exploiting the side-effects of speculatively-executed instructions using Spectre attacks. To mitigate theses attacks, popular compilers deployed a wide range of countermeasures. The security of these countermeasures, however, has not been ascertained: while some of them are believed to be secure, others are known to be insecure and result in vulnerable programs. To reason about the security guarantees of these compiler-inserted countermeasures, this paper presents a framework comprising several secure compilation criteria characterizing when compilers produce code resistant against Spectre attacks. With this framework, we perform a comprehensive security analysis of compiler-level countermeasures against Spectre attacks implemented in major compilers. This work provides sound foundations to formally reason about the security of compiler-level countermeasures against Spectre attacks as well as the first proofs of security and insecurity of said countermeasures.

## Related

Spectre attack: [https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)](https://en.wikipedia.org/wiki/Spectre_(security_vulnerability))

Meltdown and Spectre: [https://meltdownattack.com/](https://meltdownattack.com/)

## Download

PDF: [Exorcising Spectres with Secure Compilers.pdf](../file/Exorcising Spectres with Secure Compilers.pdf)