# jadx

**jadx** - Dex to Java decompiler

Command line and GUI tools for producing Java source code from Android Dex and Apk files

❗❗❗ Please note that in most cases **jadx** can't decompile all 100% of the code, so errors will occur. Check [Troubleshooting guide](https://github.com/skylot/jadx/wiki/Troubleshooting-Q&A#decompilation-issues) for workarounds

**Main features:**

- decompile Dalvik bytecode to java classes from APK, dex, aar, aab and zip files
- decode `AndroidManifest.xml` and other resources from `resources.arsc`
- deobfuscator included

**jadx-gui features:**

- view decompiled code with highlighted syntax
- jump to declaration
- find usage
- full text search
- smali debugger, check [wiki page](https://github.com/skylot/jadx/wiki/Smali-debugger) for setup and usage

Jadx-gui key bindings can be found [here](https://github.com/skylot/jadx/wiki/JADX-GUI-Key-bindings)

See these features in action here: [jadx-gui features overview](https://github.com/skylot/jadx/wiki/jadx-gui-features-overview)

[![img](https://user-images.githubusercontent.com/118523/142730720-839f017e-38db-423e-b53f-39f5f0a0316f.png)](https://user-images.githubusercontent.com/118523/142730720-839f017e-38db-423e-b53f-39f5f0a0316f.png)

## Download

- release from [github: ![Latest release](https://camo.githubusercontent.com/0d2bf856ffd8f6a4069065d5ab98ff4fb8f9b62b4645bfb868faffb4ad4caa4d/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f72656c656173652f736b796c6f742f6a6164782e737667)](https://github.com/skylot/jadx/releases/latest)
- latest [unstable build ![GitHub commits since tagged version (branch)](https://camo.githubusercontent.com/31dab54bb9b0349c1a67547aed825e6945cdf4ed6af22d9df20df116a3fcd491/68747470733a2f2f696d672e736869656c64732e696f2f6769746875622f636f6d6d6974732d73696e63652f736b796c6f742f6a6164782f6c61746573742f6d6173746572)](https://nightly.link/skylot/jadx/workflows/build-artifacts/master)

After download unpack zip file go to `bin` directory and run:

- `jadx` - command line version
- `jadx-gui` - UI version

On Windows run `.bat` files with double-click
**Note:** ensure you have installed Java 11 or later 64-bit version. For Windows, you can download it from [oracle.com](https://www.oracle.com/java/technologies/downloads/#jdk17-windows) (select x64 Installer).

## Install

1. Arch linux ![Arch Linux package](https://camo.githubusercontent.com/885453bd019c57e86c4838e8fc6a63483aaad91b83d431295c60ecd2d99e03b1/68747470733a2f2f696d672e736869656c64732e696f2f617263686c696e75782f762f636f6d6d756e6974792f616e792f6a6164783f6c6162656c3d)

   ```
   sudo pacman -S jadx
   ```

2. macOS ![homebrew version](https://camo.githubusercontent.com/e71c481160fb67a6b5c5eb061301375d61367f80768cae09b48bee137793193c/68747470733a2f2f696d672e736869656c64732e696f2f686f6d65627265772f762f6a6164783f6c6162656c3d)

   ```
   brew install jadx
   ```

3. Flathub ![Flathub](https://camo.githubusercontent.com/d10f23dc87da90a913320ee774ca833d4399628befb5af94893cffd487e60878/68747470733a2f2f696d672e736869656c64732e696f2f666c61746875622f762f636f6d2e6769746875622e736b796c6f742e6a6164783f6c6162656c3d)

   ```
   flatpak install flathub com.github.skylot.jadx
   ```

## Use jadx as a library

You can use jadx in your java projects, check details on [wiki page](https://github.com/skylot/jadx/wiki/Use-jadx-as-a-library)

## Build from source

JDK 8 or higher must be installed:

```
git clone https://github.com/skylot/jadx.git
cd jadx
./gradlew dist
```

(on Windows, use `gradlew.bat` instead of `./gradlew`)

Scripts for run jadx will be placed in `build/jadx/bin` and also packed to `build/jadx-<version>.zip`

## Links

https://github.com/skylot/jadx