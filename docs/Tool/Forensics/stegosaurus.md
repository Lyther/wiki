# stegosaurus

A steganography tool. Used when you can't find any other choices.

## Abstract

Stegosaurus is a [steganography tool](https://en.wikipedia.org/wiki/Steganography) that allows embedding arbitrary payloads in Python bytecode (pyc or pyo) files. The embedding process does not alter the runtime behavior or file size of the carrier file and typically results in a low encoding density. The payload is dispersed throughout the bytecode so tools like `strings` will not show the actual payload. Python's `dis` module will return the same results for bytecode before and after Stegosaurus is used to embed a payload. At this time, no prior work or detection methods are known for this type of payload delivery.

## Link

GitHub repo: https://github.com/AngelKitty/stegosaurus