# Zeratool

Automate exploit generate tool.

## Abstract

![zera](https://camo.githubusercontent.com/f4167f859807328b8f25e55982ff7deaa01469682bef24949d2dcdb4c4254317/68747470733a2f2f61736369696e656d612e6f72672f612f3435373936342e737667)

Automatic Exploit Generation (AEG) and remote flag capture for exploitable CTF problems

This tool uses [angr](https://github.com/angr/angr) to concolically analyze binaries by hooking printf and looking for [unconstrained paths](https://github.com/angr/angr-doc/blob/master/docs/examples.md#vulnerability-discovery). These program states are then weaponized for remote code execution through [pwntools](https://github.com/Gallopsled/pwntools) and a series of script tricks. Finally the payload is tested locally then submitted to a remote CTF server to recover the flag.

## Link

GitHub repo: https://github.com/ChrisTheCoolHut/Zeratool