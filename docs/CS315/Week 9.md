# Week9 MISC: Social Engineering

## Clone a Website

For a phishing assessment sometimes it might be useful to completely **clone a website**.

Note that you can add also some payloads to the cloned website like a BeEF hook to "control" the tab of the user. 

There are different tools you can use for this purpose:

### **wget**

```
wget -mk -nH
```

### **goclone**

```
#https://github.com/imthaghost/goclone
oclone <url>
```

### **Social Engineering Toolit**

```
#https://github.com/trustedsec/social-engineer-toolkit
```

## Detecting Phising

### **Introduction**

In order to detect a phishing attempt it's important to **understand the phishing techniques that are being used nowadays**. In the parent page of this post you can find this information, so if you aren't aware of which techniques are being used today I recommend you to go to the parent page and read at least that section.

This post is based in the idea that the **attackers will try to somehow mimic or used the victim's domain name**. If your domain is called `example.com` and you receive a phishing that is using a completely different domain name for some reason like `youwonthelottery.com`, this techniques aren't going to uncover it.

### **Domain name variations**

It's kind of **easy** to **uncover** those **phishing** attempts that will use a **similar domain** name inside the email. It's enough to **generate a list of the most probable phishing names** that an attacker may use and **check** if it's **registered** or just check if there is any **IP** using it.

#### **Finding suspicions domains**

For this purpose you can use any of the following tools. Note that these tolls will also perform DNS requests automatically to check if the domain has any IP assigned to it:

- ****[**dnstwist**](https://github.com/elceef/dnstwist)****
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)****

#### **Bitflipping**

In the world of computing, everything is stored in bits (zeros and ones) in memory behind the scenes. This applies to domains too. For example, *windows.com* becomes *01110111...* in the volatile memory of your computing device. However, what if one of these bits got automatically flipped due to a solar flare, cosmic rays, or a hardware error? That is one of the 0's becomes a 1 and vice versa. Applying this concept to DNS request, it's possible that the **domain requested** that arrives to the DNS server **isn't the same as the domain initially requested.**

For example a 1 bit modification in the domain microsoft.com can transform it into *windnws.com.* **Attackers may register as many bit-flipping domains as possible related to the victim in order to redirect legitimate users to their infrastructure**.

For more information read https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/

**All possible bit-flipping domain names should be also monitored.**

#### **Basic checks**

Once you have a list of potential suspicions domain names you should **check** them (mainly the ports HTTP and HTTPS) to **see if they are using some login form similar** to someone of the victim's domain. You could also check the port 3333 to see if it's open and running an instance of `gophish`. It's also interesting to know **how old each discovered suspicions domain is**, the younger it's the riskier it is. You can also get **screenshots** of the HTTP and/or HTTPS suspicious web page to see if it's really suspicious and in that case **access it to take a deeper look**.

#### **Advanced checks**

If you want to go one step further I would recommend you to **monitor those suspicious domains and search for more** once in a while (every day? it only takes a few seconds/minutes). You should also **check** the open **ports** of the related IPs and **search for instances of** **`gophish`** **or similar tools** (yes, attackers also make mistakes) and **monitor the HTTP and HTTPS web pages of the suspicions domains and subdomains** to see if they have copied any login form from the victims web pages. In order to **automate this** I would recommend to to have a list of login forms of the victims domains, spider the suspicions web pages and compare each login form found inside the suspicions domains with each login form of the victim's domain using something like `ssdeep`. If you have located the login forms of the suspicions domains you can try to **send junk credentials** and **check if it's redirecting you to the victims domain**.

### **Domain names using keywords**

The parent page also mentions a domain name variation technique that consist on putting the **victim's domain name inside a bigger domain** (e.g. paypal-financial.com for paypal.com).

#### **Certificate Transparency**

It's not possible to take the previous "Brute-Force" approach but it's actually **possible to uncover this phishing attempts** also thanks to certificate transparency. Every time a certificate is emitted by a CA, the details are made public. This means that reading the certificate transparency or even monitoring it, it's **possible to find domains that are using a keyword inside it's name** For example, if attackers generates a certificate of [https://paypal-financial.com](https://paypal-financial.com/), seeing the certificate it's possible to find the keyword "paypal" and know that that suspicions email is being used.

The post https://0xpatrik.com/phishing-domains/ suggest that you can use Censys to search for certificates affecting a specific keyword and filter by date (only "new" certificates) and by the CA issuer "Let's Encrypt":

![img](../assets/Week 9-1.png)

However, you can do "the same" using the free web [**crt.sh**](https://crt.sh/). You can **search for the keyword** and the **filter** the results **by date and CA** if you whish.

![img](../assets/Week 9-2.png)

Using this last option you can even use the field Matching Identities to see if any identity from the real domain matches any of the suspicious domain (note that a suspicious domain can be a false positive).

**Another alternative** is the fantastic project called [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream provides a real-time stream of newly generated certificates which you can use to detect specified keywords in (near) real-time. In fact, there is a project called [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) that does just like that.

#### **New domains**

**One last alternative** is to gather a list of **newly registered domains** for some TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) provides such service) and **check the keywords in these domains**. However, long domains usually uses one or more subdomains, therefore the keyword won't appear inside the FLD and you won't be able to find the phishing subdomain.

## Phishing Documents

Microsoft Word performs file data validation prior to opening a file. Data validation is performed in the form of data structure identification, against the OfficeOpenXML standard. If any error occurs during the data structure identification, the file being analysed will not be opened.

Usually Word files containing macros uses the `.docm` extension. However, it's possible to rename the file changing the file extension and still keep their macro executing capabilities. For example, an RTF file does not support macros, by design, but a DOCM file renamed to RTF will be handled by Microsoft Word and will be capable of macro execution. The same internals and mechanisms apply to all software of the Microsoft Office Suite (Excel, PowerPoint etc.).

You can use the following command to check which extensions are going to be executed by some Office programs:

```
assoc | findstr /i "word excel powerp"
```

DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### **Word with external image**

Go to: *Insert --> Quick Parts --> Field* ***Categories\****: Links and References,* ***Filed names\****: includePicture, and* ***Filename or URL\****:* http://%3Cip%3E/whatever

![img](../assets/Week 9-3.png)

### **Macros Code**

```
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

## **Autoload functions**

The more common they are, the more probable the AV will detect it.

- AutoOpen()
- Document_Open()

## **Malicious Macros Generators**

### **MacOS**

- **[macphish](https://github.com/cldrn/macphish)**
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Exercise

### (4 pt) Sanity Check

Got some reviews that our challenges are so hard. Frank becomes so sad because there's no difficult challenges this week. 

We even have a sanity check for the first challenge.

`flag{1_l0v3_54n17y_ch3ck_ch4ll5}`

*Hint1: the flag is in question description.*

*Hint2: the flag is in plain text.*

### (4 pt) VidCap

Found this pcap of my ex's network traffic. I knew they're streaming video but I can't extract it. Can you help me ?

*Hint1: this challenge is from COMPFEST 13.*

*Hint2: successfully extract files in the zip leads to the checkpoint.*

[video.zip](https://mega.nz/file/ug80mahR#ip4FiWbLYBN7DHeTO7ikBJEOUDYpM6oQwqdRTXcnubY)

### (4 pt) Archaeology

Windows XP is a great OS. When cleaning my Windows XP laptop, something unfortunate happened...

*Hint1: after you found the docx, use XOR brute. This isn't a macro forensics.*

[Archaeology.zip from MEGA](https://mega.nz/file/i0823AxL#28rdjtrcIE6bSF8-6Vjq9VCnESjt4QiWw-cNQt9eBys)

[Archaeology.zip from Baidu Disk](https://pan.baidu.com/s/1ZuD_pj_6ejT5cW_roPscBg) with password `l720`

