# APKTool

A tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications. It also makes working with an app easier because of the project like file structure and automation of some repetitive tasks like building apk, etc.

It is **NOT** intended for piracy and other non-legal uses. It could be used for localizing, adding some features or support for custom platforms, analyzing applications and much more.

```
$ apktool d test.apk
I: Using Apktool 2.7.0 on test.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: 1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
$ apktool b test
I: Using Apktool 2.7.0 on test
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
```

## Features

- Disassembling resources to nearly original form (including `resources.arsc`, `classes.dex`, `9.png.` and `XMLs`)
- Rebuilding decoded resources back to binary APK/JAR
- Organizing and handling APKs that depend on framework resources
- Smali Debugging (Removed in `2.1.0` in favor of [IdeaSmali](https://github.com/JesusFreke/smali/wiki/smalidea))
- Helping with repetitive tasks

## Requirements

- Java 8 (JRE 1.8)
- Basic knowledge of Android SDK, AAPT and smali

## Links

https://ibotpeaches.github.io/Apktool/

https://github.com/iBotPeaches/Apktool