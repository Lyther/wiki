# Week8 MISC: Physical Attacks

According to @Hacktricks: https://book.hacktricks.xyz/

## BIOS password

### The battery

Most of the **motherbords** have a **battery**. If you **remove** it **30min** the settings of the BIOS will be **restarted** (password included).

### Jumper CMOS

Most of the **motherboards** have a **jumper** that can restart the settings. This jumper connects a central pin with another, if you **connect thoses pins the motherbord will be reseted**.

### Live Tools

If you could **run** for example a **Kali** Linux from a Live CD/USB you could use tools like ***killCmos\*** or ***CmosPWD\*** (this last one is included in Kali) you could try to **recover the password of the BIOS**.

### Online BIOS password recovery

Put the password of the BIOS **3 times wrong**, then the BIOS will **show an error messag**e and it will be blocked. Visit the page [https://bios-pw.org](https://bios-pw.org/) and **introduce the error code** shown by the BIOS and you could be lucky and get a **valid password** (the **same search could show you different passwords and more than 1 could be valid**).

## UEFI

To check the settings of the UEFI and perform some kind of attack you should try [chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf). Using this tool you could easily disable the Secure Boot:

```
python chipsec_main.py -module exploits.secure.boot.pk
```

## RAM

### Cold boot

The **RAM memory is persistent from 1 to 2 minutes** from the time the computer is powered off. If you apply **cold** (liquid nitrogen, for example) on the memory card you can extend this time up to **10 minutes**.

Then, you can do a **memory dump** (using tools like dd.exe, mdd.exe, Memoryze, win32dd.exe or DumpIt) to analyze the memory.

You should **analyze** the memory **using volatility**.

### [INCEPTION](https://github.com/carmaa/inception)

Inception is a **physical memory manipulation** and hacking tool exploiting PCI-based DMA. The tool can attack over **FireWire**, **Thunderbolt**, **ExpressCard**, PC Card and any other PCI/PCIe HW interfaces. **Connect** your computer to the victim computer over one of those **interfaces** and **INCEPTION** will try to **patch** the **pyshical memory** to give you **access**.

**If INCEPTION succeeds, any password introduced will be vaid.**

**It doesn't work with Windows10.**

## Live CD/USB

### Sticky Keys and more

- **SETHC:** *sethc.exe* is invoked when SHIFT is pressed 5 times
- **UTILMAN:** *Utilman.exe* is invoked by pressing WINDOWS+U
- **OSK:** *osk.exe* is invoked by pressing WINDOWS+U, then launching the on-screen keyboard
- **DISP:** *DisplaySwitch.exe* is invoked by pressing WINDOWS+P

These binaries are located inside ***C:\Windows\System32\***. You can **change** any of them for a **copy** of the binary **cmd.exe** (also in the same folder) and any time that you invoke any of those binaries a command prompt as **SYSTEM** will appear.

### Modifying SAM

You can use the tool ***chntpw\*** to **modify the** ***SAM\*** **file** of a mounted Windows filesystem. Then, you could change the password of the Administrator user, for example. This tool is available in KALI.

```
chntpw -h
chntpw -l <path_to_SAM>
```

**Inside a Linux system you could modify the** ***/etc/shadow\*** **or** ***/etc/passwd\*** **file.**

### **Kon-Boot**

**Kon-Boot** is one of the best tools around which can log you into Windows without knowing the password. It works by **hooking into the system BIOS and temporarily changing the contents of the Windows kernel** while booting (new versions work also with **UEFI**). It then allows you to enter **anything as the password** during login. The next time you start the computer without Kon-Boot, the original password will be back, the temporary changes will be discarded and the system will behave as if nothing has happened. Read More: https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/

It is a live CD/USB that can **patch the memory** so you **won't need to know the password to login**. Kon-Boot also performs the **StickyKeys** trick so you could press ***Shift\*** **5 times to get an Administrator cmd**.

## **Running Windows**

### Initial shortcuts

### Booting shortcuts

- supr - BIOS
- f8 - Recovery mode
- *supr* - BIOS ini
- *f8* - Recovery mode
- *Shitf* (after the windows banner) - Go to login page instead of autologon (avoid autologon)

### **BAD USBs**

#### **Rubber Ducky tutorials**

- [Tutorial 1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
- [Tutorial 2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

- [Payloads and tutorials](https://github.com/Screetsec/Pateensy)

There are also tons of tutorials about **how to create your own bad USB**.

### Volume Shadow Copy

With administrators privileges and powershell you could make a copy of the SAM file.[ See this code]().

## Bypassing Bitlocker

Bitlocker uses **2 passwords**. The one used by the **user**, and the **recovery** password (48 digits).

If you are lucky and inside the current session of Windows exists the file ***C:\Windows\MEMORY.DMP\*** (It is a memory dump) you could try to **search inside of it the recovery password**. You can **get this file** and a **copy of the filesytem** and then use *Elcomsoft Forensic Disk Dercyptor* to get the content (this will only work if the password is inside the memory dump). You coud also **force the memory dump** using ***NotMyFault\*** of *Sysinternals,* but this will reboot the system and has to be executed as Administrator.

You could also try a **bruteforce attack** using ***Passware Kit Forensic\***.

## An Introduction to Printer Exploitation

### Preface

*Note:* As always the following is just a digest of all the things I could observe by working on printers myself or facts from stuff I read about recently.

Since this thread about the [HP printer promo videos 3](https://0x00sec.org/t/the-wolf-nothing-is-safe/3491/9) caught some attention I will try to shed some light onto the field which was displayed there.
First of all we should keep in mind this was a *promo video* made by a company.
So always ask yourself this: “How real are the displayed scenarios, or are these just ‘Hollywood fabrications’?”

I had some access to different printers over the last couple of month and learned some basic principles, which I wanna share with
you as good as possible now.
Printer use a various amount of protocols and firmwares which differ from vendor to vendor and model to model.
So this first part might be boring to some, you can try to skip the theoretical part and jump right to the exploitation paragraph, but talking about fundamentals will cover important topics.

#### Printer as an attack vector?

- So why would I even want to target a printer in the first place?
- Why not just target Desktop or Server environments with malware as usual?

We get to that in next couple of paragraphs

#### Required Skills

Not much to mention here

- basic ability to read for more than 5 minutes

------

### Printer a viable target or just wasted time?

#### Local vs Network printers

Local printers are just directly connected to a desktop PC and are rather uninteresting.
These days almost all printers seem to be network printers though.
So basically network printing enables users in locations geographically separate from each other and from their print devices to produce documents for themselves and others.
Print servers enable multiple clients to share one or more print devices.
So far so easy right?
Let’s jump directly to some highlevel view which explains every network printer quite well.

#### Highlevel view

A highlevel view of current network printers might look something like this:

```
  +----------------------------------------------------+
                       | Network printing protocols    |
   Printing channel    +-------------------------------+--+
                       |                                  |
                       | IPP, LPD, SMB, raw port 9100     |
                       |                                  |
  +--------------------------------------------------+    |
                       | job/printer control langs.  |    |
   Printer language    +-----------------------------+--+ |
                       |                                | |
                       |  PJL, PML                      | |
                       |                                | |
                       | +------------------------+     | |
                       | | Page descr. langs.     |     | |
                       | +------------------------+---+ | |
                       | |                            | | |
                       | | PS, PCL, PDF, XPS, ...     | | |
                       | |                            | | |
                       | +----------------------------+ | |
                       +--------------------------------+ |
                       +----------------------------------+
```

*Note:* This diagram might be incomplete!

=The network printing protocol acts as a channel to deploy print jobs, which either contain the page description language directly or first invoke a printer/job control language!

Let’s take a look at each of those sections in the diagram above more closely and cover some fundamentals.

------

### Fundamentals

#### Firmware

Printer use, in my experience a couple of different operating systems for embedded devices.
I’ll list a few of them here, but won’t really dive into them, since it would go beyond the scope of this article.

- Basic but slimmed down GNU/Linux, often custom tailored,
- [WindRiver Linux 54](https://www.windriver.com/products/linux/),
- [VxWorks 38](https://www.windriver.com/products/vxworks/),
- [ThreadX 28](http://rtos.com/products/threadx/).

With the different, but limited pool of printers I’ve had access to all of them had some things in common in the end.

- slimmed down instruction/command set - reduced functionality,
- ‘legacy kernels’ - often around kernel version 2.6.XYZ,
- might include ‘hidden’ functionality, which can be enabled through a little patch - e.g.: ssh files are there, but need to be enabled in config files,
- ssh is more present in printers designed for offices, compared to home printers for some reason,
- sometimes the way the firmware is stored is hilarious - e.g.: on a SD card you can remove/switch within 30 seconds of physical access

These facts show that printers might be vulnerable to certain attacks, but still these attacks
often are made more ‘complicated’, because certain functions aren’t even there or somehow have to get enabled through (remote) file system writes…

Next a wild bunch of protocols is used for communication between Printers, print servers, desktop PCs and even internally within a printer.
Let’s take a look!

#### Network printing protocols

To summarize it right away there are a bunch of ‘exotic’ protocols for network printing (NCP or AppleTalk for example)
To explain and mention them all here would be too much again.
If anyone is interested in some specifics or a follow up post I’d answer any questions there.

In the Windows world, SMB/CIFS printer are popular.
The most common printing protocols supported directly by network printers however are LPD, IPP, and raw port 9100 printing, which I will explain a bit more in depth now.
Furthermore, some devices support printing over generic protocols such as FTP or HTTP file uploads as well.

##### LPD

LPD is short for ‘Line Printer Daemon’-protocol.
It runs on port 515/TCP and can be accessed by using ‘lpr’ over the CLI.
To print things, the client sends a control file defining job/username and a data file containing the actual data to be printed.

##### IPP

IPP is an extendable protocol and based on HTTP, so it inherits all existing security features like basic authentication and SSL/TLS encryption.
To submit a print job, a HTTP POST request is sent to the IPP server, which listens on 631/TCP.
For anyone wondering CUPS is an IPP implementation, which is a default printing system in many Linux distributions and macOS X.

##### SMB

SMB, short for ‘Server Message Block’ is an application-layer network protocol, which handles file and printer sharing.
It’s used by default on Windows.
Usually it runs on 445/TCP.

##### Port 9100

Also known as ‘raw printing’, since it makes use of connecting to 9100/TCP of a network printer.
It is the default method used by CUPS and the Windows printing architecture.
Here all data sent is directly processed by the printing device, just like a parallel connection over TCP.
In contrast to LPD, IPP and SMB interpreted printer control/page description languages, this one here is capable of sending direct feedback to the client, including status and error messages.
So we have a *bidirectional channel* here, which directly can give us access to results of the Printer control languages!

#### Printer Control Languages

Basically a job control language manages settings like output trays for the current job.
It often just sits in between the printing protocol and the page description language.
Printer control and management languages are designed to affect not only a single print job but the device as a whole.
I’m not too knowledgeable here but the two most basic ones are listed below.

##### SNMP

SNMP, short for ‘Simple Network Management Protocol’ listens on 161/UDP.
Was designed to manage network components

##### PJL

PJL, short for ‘Printer Job Language’ is the kinda de-facto standard now
Can be used to manipulate general settings, also with permanent changes.
There are many dialects as vendors tend to support only a subset of the commands listed in the PJL reference and instead prefer to add proprietary ones.
PJL is also used to set the file format of the actual print data to follow, which makes it interesting for various attacks.

#### Page Description Languages (PDL)

This one basically specifies how the actual document will look like appearance wise.
Here comes the printer driver into play which kinda translate the file to be printed into a PDL that is understood by the printer.

##### PostScript (PS)

Is well known and made by Adobe and is widely used as a PDL.
PS is capable of far more than just defining the appearance of the document and handling vector graphics though.
That’s why, when used correctly, PS can be used for a variety of attacks such as denial of service (for example, through infinite loops), print job manipulation and retention as well as gaining access to the printer’s file system.

##### PCL

As a minimalist page description language supported by a wide variety of vendors and devices.
Is also a de-facto Standard nowadays.
It’s also not intended to get direct access to the underlying filesystem.
So it’s not that well suited for exploitation purposes, but still has it’s place for such purposes as well.

------

### Possible Exploits

##### Who would put a printer on the Internet?

I just leave this data as a first expression here

> shodan count port:9100 pjl
> 29111
> [7/07/20 7:42:13] dev@ops
> shodan count port:515 lpd
> 50607
> [7/07/20 7:42:46] dev@ops
> shodan count port:631 ipp
> 90760
> [7/07/20 7:43:10] dev@ops
> shodan count port:161 snmp
> 7876

Data from: 07.07.2020

#### Attack Vectors

##### Remote

As easily seen above a lot of printers are connected to the *Internet* through port 9100, which make them attackable.
You either know the IP or can just scan for some in your neighborhood radius/ check shodan.
Once you have some you might get a SSH connection going.
Often standard login credentials are still used, which you can easily scrape from the Internet…

##### Inside job

If you have physical access to the printer you can also plug in an USB drive or even a SD card.

#### Possible Mayhem one can cause…

So now we’re kinda back to the linked topic at the beginning of the small web series directed by HP.
So how realistic are the shown scenarios?

##### DoS

- Transmission Channel - basically block the/one printing port to keep the printer busy and don’t print anything anymore.
- Document processing - manipulate a Document via PDL and let the printer interpret it… e.g.: an infinite loop in PS.
- Physical damage - malware causing writes on [NVRAM chips which have a life expectancy of ~10^5 writes 30](https://en.wikipedia.org/wiki/Non-volatile_memory).

##### Privilege Escalation

- Factory defaults - reset to factory defaults to bypass authentication.
- Accounting bypass - similar thing here, printing without authentication.

##### Print Job Access

- Print job retention - Try to find stored print jobs on the printer and extract those.
- Print job manipulation - Alter print jobs. You can imagine the possible mayhem caused itself.

##### Information Disclosure

- Memory access - may lead to finding sensitive data like passwords or printed documents.
- File system access - potentially retrieve sensitive information like configuration files or stored print jobs.
- Credential disclosure - brute force attacks against changed default login credentials to gain access

##### Code Execution

- Buffer overflows - printers provide additional languages and network services, potentially prone to this kind of attack
- Firmware updates - it is common for printers to deploy firmware updates as ordinary print jobs **cough** malicious firmware **cough**
- Software packages - ‘custom tailored and manipulated printer apps’

##### Misc

- Malware - target network printers and spread it in local networks to other peers.

##### possible scenarios

Depending on the planned attack and possible access one has a variety of attack vectors.
One need more planning than others.
Some need physical access and some can be done from remote.
Combinations of those are easily possible!

For example issuing a malicious firmware update via a simple print job (possible case: no authentication needed), which extracts sensitive data and renders the printer useless.
-Printer ‘ransomware’ may be a thing, even if it sounds kinda weird.

So to conclude this section, I think the shown attacks in the videos were presented a tad to ‘flashy’, but are indeed possible depending on the printers and network they are placed in.

------

#### Tools

A lot of these techniques mentioned above need some serious work or knowledge about the underlying structure ( e.g.: used PDL, PCL).
Even though these might be fairly easily found out using manuals or online search it’s still a hassle and extra work.
So people already made our lifes more easy by providing tools for almost all tasks mentioned above :).

##### BeEF

The Browser Exploitation Framework (BeEF) is a penetration testing tool that focuses on the web browser.
It allows the penetration tester to assess the actual security posture of a target environment by using client-side attack vectors.
This is not really printer specific, **but** it is a framework to implement [cross-site printing 48](https://www.cert-ist.com/public/en/SO_detail?code=Cross_Site_Printing) functionality.

##### Praeda

Praeda - “An Automated Printer Data Harvesting Tool” written in perl.
Also a tool to help pentesters to gather usable data during security assessment jobs.
Praeda systematically collects sensitive information from the printer’s embedded web server.
This includes device passwords, usernames, email addresses which might be available publicly on the web interface.

##### [PRET 328](https://github.com/RUB-NDS/PRET)

This one is real nifty tool written in python to check for basically every attack vector I mentioned above.
It tries to connect to the printer via network or USB and tries to exploit the used printer languages, currently supported are PS, PJL and PCL.
When successfully connected one has a ton of available commands.
A full list can be found on the Github, linked below.

##### LES

Linux Exploit Suggester is a neat little perl script, which gives some options for possible exploits depending on your kernel.
As stated above the kernel versions for embedded operating systems are often far lower, compared to current linux based desktop or server distributions.
So old, usually fixed exploit techniques might still be viable here!

*Note:* It is likely, that perl is not present in it’s full range and copying it to a printer is extra work.
Luckily one can run simply run in a desktop environment and specifying the kernel you want to exploit

------

#### My home printer - a journey to find a way in!

Ok what is a basic plan to concentrate on when trying to exploit a printer?
I’ve given a lot of theory until this point, as well as some “Do’s” and “Mights”.
Maybe you’ve got some ideas on your own already, but here’s a little experimental journey from me.

So first thing that is obvious is to check for open ports and an OS fingerprint.
Luckily we have nmap.
Nmap is bae for this.

##### Where’s the door?

```
$ sudo nmap 192.168.1.108
Starting Nmap 7.01 ( https://nmap.org ) at 2017-09-11 20:13 CEST
Nmap scan report for 192.168.1.108
Host is up (0.031s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
80/tcp   open  http
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
515/tcp  open  printer
631/tcp  open  ipp
9100/tcp open  jetdirect
MAC Address: 44:D2:44:1C:73:E2 (Seiko Epson)

Nmap done: 1 IP address (1 host up) scanned in 2.04 seconds

Device type: specialized
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.31 - 2.6.35 (embedded)
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
$
```

So we have the usual printing ports open, as well as some other basic ones.
It is running an older Linux as well, so no big surprise there!
No open 22/TCP port though.
So causing mayhem on the file system is not possible as of now.

##### PRET and done?

I’ve praised PRET quite a bit above, so let’s give it a try to check if my Epson printer has a nice, hopefully standard set of supported printer languages!

```
$ python pret.py 192.168.1.108 -s PS

Checking for IPP support:       found
Checking for HTTP support:      found
Checking for SNMP support:      found
Checking for PS support:        not found
$

$ python pret.py 192.168.1.108 -s Pjl
Checking for IPP support:       found
Checking for HTTP support:      found
Checking for SNMP support:      found
Checking for PJL support:       not found
$

$ python pret.py 192.168.1.108 -s PCL
Checking for IPP support:       found
Checking for HTTP support:      found
Checking for SNMP support:      found
Checking for PCL support:       not found
$
```

So no SSH and not even a standard version here…
Most likely the result of my vendor using some exotic stuff again and not keeping things simple …

Anyway using PRET is easy and self explanatory, once connected a help function will give you an overview of available stuff!
From checking the file-system. creating directories, changing configuration files or even dumping the whole NVRAM.
PRET can do it all (in theory that is ).

After trying a few things to find a way to make PRET work for me I trashed that idea for now and moved on!

##### LES

So I wanted to have some fun now after the two disappointing results :D.
So let’s dig deeper into what Linux exploits might get suggested for our version!

```
$ perl Linux_Exploit_Suggester.pl -k 2.6.31

Kernel local: 2.6.31

Searching among 65 exploits...

Possible Exploits:
[+] american-sign-language
   CVE-2010-4347
   Source: http://www.securityfocus.com/bid/45408/
[+] can_bcm
   CVE-2010-2959
   Source: http://www.exploit-db.com/exploits/14814/
[+] do_pages_move
   Alt: sieve    CVE-2010-0415
   Source: Spenders Enlightenment
[+] half_nelson
   Alt: econet    CVE-2010-3848
   Source: http://www.exploit-db.com/exploits/6851
[+] half_nelson1
   Alt: econet    CVE-2010-3848
   Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson2
   Alt: econet    CVE-2010-3850
   Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson3
   Alt: econet    CVE-2010-4073
   Source: http://www.exploit-db.com/exploits/17787/
[+] msr
   CVE-2013-0268
   Source: http://www.exploit-db.com/exploits/27297/
[+] pipe.c_32bit
   CVE-2009-3547
   Source: http://www.securityfocus.com/data/vulnerabilities/exploits/36901-1.c
[+] pktcdvd
   CVE-2010-3437
   Source: http://www.exploit-db.com/exploits/15150/
[+] ptrace_kmod2
   Alt: ia32syscall,robert_you_suck    CVE-2010-3301
   Source: http://www.exploit-db.com/exploits/15023/
[+] rawmodePTY
   CVE-2014-0196
   Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
[+] rds
   CVE-2010-3904
   Source: http://www.exploit-db.com/exploits/15285/
[+] reiserfs
   CVE-2010-1146
   Source: http://www.exploit-db.com/exploits/12130/
[+] video4linux
   CVE-2010-3081
   Source: http://www.exploit-db.com/exploits/15024/
$
```

*Note:* If these are viable and meet all dependencies has to be checked of course, but a brief look at them made me decide not to spend too much effort here.

##### Manual PJL Injection

So I thought why not check for PJL again and try invoking some command strings manually in combination with netcat as a listener!

So I tried using:

```
echo "@PJL FSUPLOAD FORMAT:BINARY NAME="../../etc/passwd" OFFSET=0 SIZE=648" | nc -v -v 192.168.1.108 9100
# If successful this should display the */etc/passwd* file.
```

or

```
echo "@PJL INFO ID" | nc -v -v 192.168.1.108 9100
# If successful this should get the *printer’s device information*
```

as well as other PJL command injecting techniques, but my printer is not accepting any of these.
It’s not reacting at all to this kind of ‘attack’…

I’m not knowledgeable enough to launch this with PS and PCL as well, because their command syntax differs greatly (obviously).
I’m remaining with a note to search for PS and PCL attack strings.

##### A PRET test script to the rescue?

So PRET doesn’t work for my home printer as seen above.
Interestingly I found that there is a script “hidden” within the PRET source folder called “lpdtest.py”
It can test for known, but older (like really older) vulnerabilities within the Line Printer Daemon, listed [here 60](http://insecure.org/sploits/lpd.protocol.problems.html).
This involves some basic tests:

###### ‘get’ Test

Trying to get (aka print) a file from printer’s file system.

$ lpdtest.py printer get /etc/passwd
$ lpdtest.py printer get …/…/…/etc/passwd

etc…

###### ‘in’ Test

This test is for fuzzing around with user input (hostname,username, jobname, filenames, etc.).
This might be useful to test for interpretation of shell commands…

```
# Test for environment variables
$ lpdtest.py printer in '$UID'

# Test for pipes and redirects
$ lpdtest.py printer in '| pwd'
$ lpdtest.py printer in '>/etc/passwd'

# Test for backticks
$ lpdtest.py printer in '`ls`'

# Test for [shellshock (CVE-2014-6271)](http://seclists.org/oss-sec/2014/q3/650)
$ lpdtest.py printer in '() {:;}; /bin/ping -c1 1.2.3.4'
```

As expected these attacks were already fixed.
My printer spit out a few pages with lines like

“If you can read this lpdtest.py XYZ failed!”

So the result here some wasted paper and ink…

------

### Summary

#### Why Printer Exploitation?

- (most) printers are already full blown computers!
  - Printer as port/network/exploits scanner
  - Computing/hash-cracking/sniffing
  - Malware upload
  - “Stealth”/“uncleanable” command and control
  - Unencrypted data theft

#### Afterthoughts

- How many people would expect their printers is infected?
- How many users/admins/security-auditors audit and hard secure their network printers?
- How many persons or anti malware products could clean such a malware?
- …?

#### Outlook and closing words

If I get the hands on some nicer printer I will deliver some exploit stuff later on I promise.
If I get some more time to get a breakdown of my current home printer so I can take a look under the hood and to figure something out.
An example here would be to capture a firmware update and trying to unpack/reverse that one.
This would take a lot more time and preparation of my part, which would cause serious delay to this article as well.

So I’m keeping it rather open ended now, but I hope I could inspire some minds here to take a closer look as well.
Furthermore I hope this article reached the people who were interested and were able learn some things.
So if you want to try to exploit your own device, just try it out!
Remember:

- Find a way into the system,
- Check for the used printer languages and try code injection techniques for these,
- Try dumping the file system directory structure from the web interface,
- Upload self created “malicious” firmware if it is supported,
- Find a new way

I’m looking forward to feedback and improvement suggestions.

#### Further readings

##### Article related resources:

- [LPD RFC 17](https://www.ietf.org/rfc/rfc1179.txt)
- [SMB RFC 17](http://www.icir.org/gregor/tools/ms-smb-protocols.html)
- [IPP RFC 16](https://www.ietf.org/wg/concluded/ipp.html)
- [How Network Printing Works 11](https://technet.microsoft.com/en-us/library/cc783789(v=ws.10).aspx)
- [PostScript Manual 7](https://www.adobe.com/products/postscript/pdfs/PLRM.pdf)
- [BeEF 18](http://beefproject.com/)
- [Praeda 18](https://github.com/percx/Praeda)
- [PRET 328](https://github.com/RUB-NDS/PRET)
- [Linux Exploit Suggester 31](https://github.com/PenturaLabs/Linux_Exploit_Suggester)
- [Printer Security Test Cheat Sheet 44](http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet)
- [Hacking Printers Wiki 27](http://hacking-printers.net/wiki/index.php/Main_Page)

##### Extras:

- [Running DOOM on a Printer 61](https://www.contextis.com/blog/hacking-canon-pixma-printers-doomed-encryption)
- [From patched to Pwnd 23](http://foofus.net/goons/percx/Xerox_hack.pdf)
- [Thousands of printers hacked across the globe after critical flaw exposed 25](http://www.techradar.com/news/thousands-of-printers-hacked-across-the-globe-after-critical-flaw-exposed)
- [Cross_Site_Printing 26](https://helpnetsecurity.com/dl/articles/CrossSitePrinting.pdf)

## Exercise

### (4 pt) GO!! Chase the free wave!

[-] ~~Hackergame 2021 challenge "去吧！追寻自由的电波"~~

[+] Inspired by Hackergame. Original created challenge.

[an interesting story]

OK now you have this mp3 file, please find the flag.

[video.mp3](file/chall8-1.mp3)

*Hint1: it's too fast to understand!*

*Hint2: if I can let the time move backwards, this might be easier.*

*Hint3: some online OCR might be helpful. For example, [https://speech-to-text-demo.ng.bluemix.net/](https://speech-to-text-demo.ng.bluemix.net/)*

### (4 pt) Mechanical Keyboard

Have you faced the situation, that your roommate is playing games so late and the sound of mechanical keyboard is super noisy?

Meanwhile, especially you have midterm exam the next day.

You decide to record this sound and try to find some interesting key taps from your roommate.

(Account password, secret chat with girlfriend, or pxxxhub keywords...)

[dist.zip](file/chall8-2.zip)

*Hint1: the key taps only contain lower case characters and spaces.*

*Hint2: keyboard sniffing paper: [https://www.davidsalomon.name/CompSec/auxiliary/KybdEmanation.pdf](https://www.davidsalomon.name/CompSec/auxiliary/KybdEmanation.pdf)*

*Hint3: online key tap detector: [https://keytap2.ggerganov.com/](https://keytap2.ggerganov.com/)*

*Hint4: another (faster) method: recognize key tap sound, generate a substitution cipher and break.*

*Hint5: flag only contains lower case characters and underline (replace all spaces to underlines).*

Example program to generate key sound average:

```python
from scipy.io import wavfile
samplerate, data = wavfile.read('./output.wav')

i = 0
countsilent = 0
samplefound = 0

avg = []
start = 0
end = 0
avg.append([0])

for sample in data:
    i+=1	
    if(sample[1]<100):
        countsilent += 1
    if(countsilent > 10000 and sample[1]>100):
        countsilent = 0
        #print(str(i)+": sample found")
        start = i
        samplefound = 1
    if(countsilent > 8000 and samplefound==1):
        samplefound = 0
        #print(str(i)+": sample ended")
        end = i
        avg[len(avg)-1]=avg[len(avg)-1]/(end-start)
        print("avg: "+str(avg[len(avg)-1]))
        avg.append([0])
    if (samplefound == 1):
        avg[len(avg)-1] += sample[1]
```

Example program to map sound to character:

```python
alphabet = "abcdefghijklmnopqr stuvwxyz"
avg = {}

i=0

res=""

with open("avg") as file:
    for line in file:
        value = line.rstrip()[6:-1]
        #print(value)
        if str(value) not in avg:
            avg[str(value)]=alphabet[i]
            i+=1
        res+=avg[str(value)]
print(avg)
print(res)
```

Online substitution cipher solver: [https://www.boxentriq.com/code-breaking/cryptogram](https://www.boxentriq.com/code-breaking/cryptogram)

### (2 pt) Free USB

A stranger has left his USB on my desk.

[plug in...]

OMG my mouse is out of control!

[usb.pcapng](file/chall8-3.pcapng)

*Hint1: packet is a USB capture, used for Logitech Optical Mouse.*

*Hint2: IRP ID is the only part changes in capture, which represents the mouse move.*

*Hint3: Gnuplot is an application to simulate mouse clicks.*

*Hint4: the first word in flag is "tHE".*

