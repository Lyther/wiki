# Ciphey

⚡ Automatically decrypt encryptions without knowing the key or cipher, decode encodings, and crack hashes ⚡

## 🤔 What is this?

Input encrypted text, get the decrypted text back.

> "What type of encryption?"

That's the point. You don't know, you just know it's possibly encrypted. Ciphey will figure it out for you.

Ciphey can solve most things in 3 seconds or less.

![Ciphey demo](../../assets/Ciphey_demo_hd.gif)

Ciphey aims to be a tool to automate a lot of decryptions & decodings such as multiple base encodings, classical ciphers, hashes or more advanced cryptography.

If you don't know much about cryptography, or you want to quickly check the ciphertext before working on it yourself, Ciphey is for you.

**The technical part.** Ciphey uses a custom built artificial intelligence module (*AuSearch*) with a *Cipher Detection Interface* to approximate what something is encrypted with. And then a custom-built, customisable natural language processing *Language Checker Interface*, which can detect when the given text becomes plaintext.

No neural networks or bloated AI here. We only use what is fast and minimal.

And that's just the tip of the iceberg. For the full technical explanation, check out our [documentation](https://github.com/Ciphey/Ciphey/wiki).

## ✨ Features

- **50+ encryptions/encodings supported** such as binary, Morse code and Base64. Classical ciphers like the Caesar cipher, Affine cipher and the Vigenere cipher. Along with modern encryption like repeating-key XOR and more. **[For the full list, click here](https://github.com/Ciphey/Ciphey/wiki/Supported-Ciphers)**
- **Custom Built Artificial Intelligence with Augmented Search (AuSearch) for answering the question "what encryption was used?"** Resulting in decryptions taking less than 3 seconds.
- **Custom built natural language processing module** Ciphey can determine whether something is plaintext or not. Whether that plaintext is JSON, a CTF flag, or English, Ciphey can get it in a couple of milliseconds.
- **Multi Language Support** at present, only German & English (with AU, UK, CAN, USA variants).
- **Supports encryptions and hashes** Which the alternatives such as CyberChef Magic do not.
- **[C++ core](https://github.com/Ciphey/CipheyCore)** Blazingly fast.

## Links

https://github.com/Ciphey/Ciphey