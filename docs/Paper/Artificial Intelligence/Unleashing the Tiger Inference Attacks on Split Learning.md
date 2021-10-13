# Unleashing the Tiger Inference Attacks on Split Learning

*[Submitted on 4 Dec 2020 (*[v1](https://arxiv.org/abs/2012.02670v1)*), last revised 21 Aug 2021 (this version, v4)]*

Authors: [Dario Pasquini](https://arxiv.org/search/cs?searchtype=author&query=Pasquini%2C+D), [Giuseppe Ateniese](https://arxiv.org/search/cs?searchtype=author&query=Ateniese%2C+G), [Massimo Bernaschi](https://arxiv.org/search/cs?searchtype=author&query=Bernaschi%2C+M)

Comments: To appear in the proceedings of: ACM Conference on Computer and Communications Security 2021 (CCS21)

Subjects: Cryptography and Security (cs.CR); Machine Learning (cs.LG)

## Abstract

We investigate the security of Split Learning -- a novel collaborative machine learning framework that enables peak performance by requiring minimal resources consumption. In the present paper, we expose vulnerabilities of the protocol and demonstrate its inherent insecurity by introducing general attack strategies targeting the reconstruction of clients' private training sets. More prominently, we show that a malicious server can actively hijack the learning process of the distributed model and bring it into an insecure state that enables inference attacks on clients' data. We implement different adaptations of the attack and test them on various datasets as well as within realistic threat scenarios. We demonstrate that our attack is able to overcome recently proposed defensive techniques aimed at enhancing the security of the split learning protocol. Finally, we also illustrate the protocol's insecurity against malicious clients by extending previously devised attacks for Federated Learning. To make our results reproducible, we made our code available at [this https URL](https://github.com/pasquini-dario/SplitNN_FSHA).

## Related

GitHub repo: [https://github.com/pasquini-dario/SplitNN_FSHA](https://github.com/pasquini-dario/SplitNN_FSHA)

## Download

PDF: [Unleashing the Tiger Inference Attacks on Split Learning.pdf](../file/Unleashing the Tiger Inference Attacks on Split Learning.pdf)