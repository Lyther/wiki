# Snipuzz: Black-box Fuzzing of IoT Firmware via Message Snippet Inference

*[Submitted on 12 May 2021 (*[v1](https://arxiv.org/abs/2105.05445v1)*), last revised 21 May 2021 (this version, v2)]*

Authors: [Xiaotao Feng](https://arxiv.org/search/cs?searchtype=author&query=Feng%2C+X) (1), [Ruoxi Sun](https://arxiv.org/search/cs?searchtype=author&query=Sun%2C+R) (2), [Xiaogang Zhu](https://arxiv.org/search/cs?searchtype=author&query=Zhu%2C+X) (1), [Minhui Xue](https://arxiv.org/search/cs?searchtype=author&query=Xue%2C+M) (2), [Sheng Wen](https://arxiv.org/search/cs?searchtype=author&query=Wen%2C+S) (1), [Dongxi Liu](https://arxiv.org/search/cs?searchtype=author&query=Liu%2C+D) (3), [Surya Nepal](https://arxiv.org/search/cs?searchtype=author&query=Nepal%2C+S) (3), [Yang Xiang](https://arxiv.org/search/cs?searchtype=author&query=Xiang%2C+Y) (1) ((1) Swinburne University of Technology, (2) The University of Adelaide, (3) CSIRO Data61)

Comments: Accepted to ACM CCS 2021

Subjects: Cryptography and Security (cs.CR)

## Abstract

The proliferation of Internet of Things (IoT) devices has made people's lives more convenient, but it has also raised many security concerns. Due to the difficulty of obtaining and emulating IoT firmware, the black-box fuzzing of IoT devices has become a viable option. However, existing black-box fuzzers cannot form effective mutation optimization mechanisms to guide their testing processes, mainly due to the lack of feedback. It is difficult or even impossible to apply existing grammar-based fuzzing strategies. Therefore, an efficient fuzzing approach with syntax inference is required in the IoT fuzzing domain. To address these critical problems, we propose a novel automatic black-box fuzzing for IoT firmware, termed Snipuzz. Snipuzz runs as a client communicating with the devices and infers message snippets for mutation based on the responses. Each snippet refers to a block of consecutive bytes that reflect the approximate code coverage in fuzzing. This mutation strategy based on message snippets considerably narrows down the search space to change the probing messages. We compared Snipuzz with four state-of-the-art IoT fuzzing approaches, i.e., IoTFuzzer, BooFuzz, Doona, and Nemesys. Snipuzz not only inherits the advantages of app-based fuzzing (e.g., IoTFuzzer, but also utilizes communication responses to perform efficient mutation. Furthermore, Snipuzz is lightweight as its execution does not rely on any prerequisite operations, such as reverse engineering of apps. We also evaluated Snipuzz on 20 popular real-world IoT devices. Our results show that Snipuzz could identify 5 zero-day vulnerabilities, and 3 of them could be exposed only by Snipuzz. All the newly discovered vulnerabilities have been confirmed by their vendors.

## Download

PDF: [Snipuzz Black-box Fuzzing of IoT Firmware via Message Snippet Inference.pdf](../file/Snipuzz Black-box Fuzzing of IoT Firmware via Message Snippet Inference.pdf)