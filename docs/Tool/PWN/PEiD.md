# PEiD

## Description

- PEiD detects most common packers, cryptors and compilers for PE files.
- It can currently detect more than 470 different signatures in PE files.
- It seems that the official website (www.peid.info) has been discontinued. Hence, the tool is no longer available from the official website but it still hosted on other sites.

## Installation

### PEiD

- Go to http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml
- Download PEiD-0.95-20081103.zip.
- Uncompress the archive. You should have a similar tree:

```
.
├── external.txt
├── PEiD.exe
├── plugins
│   ├── GenOEP.dll
│   ├── ImpREC.dll
│   ├── kanal.dll
│   ├── kanal.htm
│   └── ZDRx.dll
├── pluginsdk
│   ├── C++
│   │   ├── defs.h
│   │   └── null.c
│   ├── Delphi
│   │   └── Sample.dpr
│   ├── MASM
│   │   ├── compile.bat
│   │   ├── masm_plugin.asm
│   │   └── masm_plugin.def
│   ├── PowerBASIC
│   │   └── PEiD_Plugin.bas
│   └── readme.txt
├── readme.txt
└── userdb.txt
```

### Signatures

Update your signatures (initial file is empty). Replace the initial userdb.txt file with one of these files:

- http://handlers.sans.org/jclausing/userdb.txt
- [http://reverse-engineering-scripts.googlecode.com/files/UserDB.TXT](https://reverse-engineering-scripts.googlecode.com/files/UserDB.TXT)
- http://research.pandasecurity.com/blogs/images/userdb.txt

## Interface

#### Main interface

[![Peid.png](https://www.aldeid.com/w/images/c/c6/Peid.png)](https://www.aldeid.com/wiki/File:Peid.png)

#### Section Viewer

[![Peid-ep-section.png](https://www.aldeid.com/w/images/7/7a/Peid-ep-section.png)](https://www.aldeid.com/wiki/File:Peid-ep-section.png)

#### PE disassembler

[![Peid-1st-bytes.png](https://www.aldeid.com/w/images/a/a1/Peid-1st-bytes.png)](https://www.aldeid.com/wiki/File:Peid-1st-bytes.png)

#### PE details

[![Peid-subsytem.png](https://www.aldeid.com/w/images/1/11/Peid-subsytem.png)](https://www.aldeid.com/wiki/File:Peid-subsytem.png)

#### Extra information

[![Peid-menu-1.png](https://www.aldeid.com/w/images/0/0d/Peid-menu-1.png)](https://www.aldeid.com/wiki/File:Peid-menu-1.png)

#### Menu

##### Screenshot

[![Peid-menu-2.png](https://www.aldeid.com/w/images/8/8d/Peid-menu-2.png)](https://www.aldeid.com/wiki/File:Peid-menu-2.png)

##### Generic OEP Finder

In some cases, PEiD can find the Original Entry Point (OEP) of a packed executable:

[![PEiD-generic-oep-finder.png](https://www.aldeid.com/w/images/1/17/PEiD-generic-oep-finder.png)](https://www.aldeid.com/wiki/File:PEiD-generic-oep-finder.png)

### Krypto Analyzer

[![Peid-kanal.png](https://www.aldeid.com/w/images/e/e3/Peid-kanal.png)](https://www.aldeid.com/wiki/File:Peid-kanal.png)