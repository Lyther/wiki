# Fuzzy Message Detection

Authors: *Gabrielle Beck and Julia Len and Ian Miers and Matthew Green*

Category / Keywords: public-key cryptography / privacy, encryption, cryptocurrency

Original Publication (with major differences): ACM CCS

## Abstract

Many privacy-preserving protocols employ a primitive that allows a sender to "flag" a message to a recipient's public key, such that only the recipient (who possesses the corresponding secret key) can detect that the message is intended for their use. Examples of such protocols include anonymous messaging, privacy-preserving payments, and anonymous tracing. A limitation of the existing techniques is that recipients cannot easily outsource the detection of messages to a remote server, without revealing to the server the exact set of matching messages. In this work we propose a new class of cryptographic primitives called fuzzy message detection schemes. These schemes allow a recipient to derive a specialized message detection key that can identify correct messages, while also incorrectly identifying non-matching messages with a specific and chosen false positive rate pp. This allows recipients to outsource detection work to an untrustworthy server, without revealing precisely which messages belong to the receiver. We show how to construct these schemes under a variety of assumptions; describe several applications of the new technique; and show that our schemes are efficient enough to use in real applications.

## Download

PDF: [Fuzzy Message Detection.pdf](../file/Fuzzy Message Detection.pdf)