# Week4 WEB: Information Discovery

According to @d00mfist: https://d00mfist.gitbooks.io/ctf/content/

## Information Discovery

So once you have decided on a target you want to start your recon-process.

The recon-phase is usually divided up into two phases.

1. Passive information gathering / OSINT This is when you check out stuff like:
   - Web information
   - Email Harvesting
   - Whois enumeration
2. Active information gathering

This is when you start scanning the target with your different tools.

## Passive information gathering

It is passive in the meaning that it doesn't directly send packets to the service. But in any other sense of the word there is nothing passive about this phase.

### Visit the website

Okay, I guess this actually sends packets to the target, but whatever. Visit the page, look around, read about the target. What do they do?

### Whois

Find out who is behind the website.

Resolve the DNS

```
host website.com
nslookup website.com
```

The the IP address and check it with `whois`

```
whois 192.168.1.101
```

### Netcraft

Most of the info found on netcraft is not unique. It is basic whois info. But one thing is really good, it lists the different IP-addresses the page has had over the years. This can be a good way to **bypass cloudflare** and other services that hide the real IP. Using netcraft we can find the IP that was in use before they implemented cloudflare.

Another detail that is good to know is the **hosting-company** or **domain-provider**. Those details can be used if we want to try some **social-engineering or spear-phishing attack**.

[Netcraft](https://www.netcraft.com/)

## Find Subdomains

Finding subdomains is fundamental. The more subdomains you find, the bigger attack surface you have. Which means bigger possibility of success.

For now this seems to be a very comprehensive list of tools to find subdomains. https://blog.bugcrowd.com/discovering-subdomains

## DNS Basics

This is the best article I have found about how the DNS-system works. Form the highest to the lowest level.

[An introduction to dns-terminology components and concepts](https://www.digitalocean.com/community/tutorials/an-introduction-to-dns-terminology-components-and-concepts)

Before we begin to look at the specific techniques that exists to find subdomains, lets try to understand what subdomains are and how they work.

**A - records**

A stands for **address**.

The A record maps a name to one or more IP addresses, when the IP are known and stable. So that would be 123.244.223.222 => example.com

**AAAA** - points to a IPv6 Record

**CNAME**

The CNAME record connects a name to another name. An example of that would be:

```
www.example.com,CNAME,www.example.com.cdn.cloudflare.net.
```

Another example is. If you have the domains mail.example.com and webmail.example.com. You can have webmail.example.com point to mail.example.com. So anyone visiting webmail.example.com will see the same thing as mail.example.com. It will NOT redirect you. Just show you the same content.

Another typical usage of CNAME is to link www.example.com to example.com

CNAME is quite convenient. Because if you change the A-record. The IP-address, you don't need to change the other subdomains, like ftp.example.com or www.example.com. Since they both point to example.com, which is a A-record and points directly to the IP.

Another note. If foo.example.com points to bar.example.com, that mean that bar.example.com is the CNAME (Canonical/real/actual Name) of foo.example.com.

**Alias**

Kind of like CNAME in that it points to another name, not an IP.

**MX - Mail exchange**

https://en.wikipedia.org/wiki/MX_record

## Find Subdomains

Finding subdomains is fundamental. The more subdomains you find, the bigger attack surface you have. Which means bigger possibility of success.

For now this seems to be a very comprehensive list of tools to find subdomains. https://blog.bugcrowd.com/discovering-subdomains

Some tools find some stuff, other tools other stuff. So your best bet is to use a few of them together. Don't forget to brute-force recursively!

### recon-ng

In order to find subdomains we can use the recon-ng framework. It has the same basic structure as metasploit. You can learn more about this tool in the tools-section.

```bash
recon-ng

use use recon/domains-hosts/

# This will give you a vast amount of alternatives.

show options

set source cnn.com
```

All these subdomains will be saved in `hosts`, which you can access though: `show hosts`

If some of these subdomains are not given IPs automatically you can just run

```
use recon/hosts-hosts/resolve
run
```

And it will resolve all the hosts in the hosts-file.

### Google Dorks

Using google we can also find subdomains.

This will only give us the subdomains of a site.

```
site:msn.com -site:www.msn.com
site:*.nextcloud.com
```

To exclude a specific subdomain you can do this:

```
site:*.nextcloud.com -site:help.nextcloud.com
```

### subbrute.py

The basic command is like this

```
./subbrute.py -p cnn.com
```

https://github.com/TheRook/subbrute

### Knock

I haven't tested this yet. https://github.com/guelfoweb/knock

### Being smart

You also have to look at what kind of system the target has. Some web-apps give their clients their own subdomains. Like github.

Check out the homepage Often companies brag about their clients. You can use this to guess the subdomains of some clients.

### Reverse DNS-lookup

If you manage to figure out the IP range that the target owns (see section about nmap below). You can see which machines are online. And then you can run a script to find out the domain-addresses of those machines. That way you might find something new.

The text-file onlyIps.txt is a textfile with one IP-address on each line.

```
#!/bin/bash

while read p; do
  echo $p;
  host  $p
done <onlyIps.txt
```

Here are some more tools that can do reverse lookup http://www.cyberciti.biz/faq/how-to-test-or-check-reverse-dns/

### Online tools

#### DNSDumpster

https://dnsdumpster.com/

#### Pentest-tools

https://pentest-tools.com/information-gathering/find-subdomains-of-domain

#### Intodns

http://www.intodns.com/

#### DNSStuff

This tool doesn't enumerate subdomains per se. But it hands of a lot of information about domains. http://www.dnsstuff.com/

## Bypassing CloudFlare

https://www.ericzhang.me/resolve-cloudflare-ip-leakage/

This tool can be used to find old IPs. It could mean that the http://toolbar.netcraft.com/site_report?url=lyst.com

### Brute force dictionaries

If you try to brute force the domains it is a good idea to have a good dictionary. That can be found here:

Bitquark https://github.com/bitquark/dnspop

SecList https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

## DNS Zone Transfer Attack

Sometimes DNS servers are misconfigured. The DNS server contains a Zone file which it uses to replicate the map of a domain. They should be configured so that only the replicating DNS-server can access it, but sometimes it is misconfigured so anyone can request the zone file, and thereby recieve the whole list of subdomains. This can be done the following way:

To do this we first need to figure out which DNS-servers a domain has.

```
host -t ns wikipedia.com
host -l wikipedia.com ns1.wikipedia.com
```

This can also be done with tools such as dnsrecon and dnsenum.

https://security.stackexchange.com/questions/10452/dns-zone-transfer-attack

## Search Engine Discovery

Search engines can be very useful for finding information about the target. Search engines can be used for two things:

- Finding sensitive information on the domain that you are attacking
- Finding sensitive information about the company and its employees in on other parts of the internet. Like forums, newsgroups etc.

Remember that the world is bigger than google. So test out the other search engines.

Baidu, binsearch.info, Bing, DuckDuckGo, ixquick/Startpage, Shodan,PunkSpider

Google is a good tool to learn more about a website.

### Finding specific filetypes

```
filetype:pdf
```

#### Search within webaddress

```
site:example.com myword
```

#### Find in url

```
inurl:test.com
```

#### Wild cards

You can use the asterisk to as a wildcard:

```
*
```

Example:

```
"I've been * for a heart"
```

This will return answers where * is anything.

### Exclude words

```
-
```

the dash excludes a specific word

This query searches for pages that used the word bananasplit.

```
-banana bananasplit
```

#### Cached version

So if a website has been taken down you can still find the cached version, of the last time google visited the site

```
cache:website.com
```

https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf

### Examples

Find login-pages on sites that use the ending .bo. For bolivia.

```
site:bo inurl:admin.php
```

## Active information gathering

Once the passive phase is over it is time to move to the active phase. In this phase we start interacting with the target.

### Netdiscover

This tool is used to scan a network for live machines.

```
netdiscover -r 192.168.1.1/24
```

### Nikto

Nikto is a good tool to scan webservers. It is very intrusive.

```
nikto -host 192.168.1.101
```

## Port Scanning

### TLDR

```
# Stealthy
nmap -sS 10.11.1.X

# Scan all ports, might take a while.
nmap 10.11.1.X -p-

# Scan for UDP
nmap 10.11.1.X -sU
unicornscan -mU -v -I 10.11.1.X

# Scan for version, with NSE-scripts and trying to identify OS
nmap 10.11.1.X -sV -sC -O

# All out monsterscan
nmap -vvv -Pn -A -iL listOfIP.txt

# Fast scan
nmap 10.11.1.X -F

# Only scan the 100 most common ports
nmap 10.11.1.X --top-ports 100
```

## Nmap

Now that you have gathered some IP addresses from your subdomain scanning it is time to scan those addresses. You just copy-paste those addresses and add them to a file, line by line. Then you can scan all of them with nmap at the same time. Using the `-iL` flag.

### Basics - tcp-connect scan

Okay, so a bit of the basics of Nmap and how it works. When one machine initiate a connection with another machine using the **transmission-control protocol (tcp)** it performs what is know as a three-way handshake. That means:

```
machine1 sends a syn packet to machine2
machine2 send a syn-ack packet to machine1
machine1 sends a ack packet to machine2.
```

If machine2 responds with a syn-ack we know that that port is open. This is basically what nmap does when it scans for a port. If machine1 omits the last ack packet the connection is not made. This can be a way to make less noise.

This is the default mode for nmap. If you do not add any flags and scan a machine this is the type of connection it creates.

### "Stealthy" -sS

By adding the `-sS` flag we are telling nmap to not finalize the three way handshake. It will send a `syn`, receive `syn-ack` (if the port is open), and then terminate the connection. This used to be considered stealthy before, since it was often not logged. However it should not be considered stealthy anymore.

In the flag I imagine that the first `s` stands for scan/scantype and the second `S` stands for `syn`.

So `-sS` can be read as **scantype syn**

### UDP scan

UDP is after TCP the most common protocol. DNS (53), SNMP (161/162) and DHCP (67/68) are some common ones. Scanning for it is slow and unreliable.

```
-sU
```

#### Output scan to a textfile

Not all output works with grepable format. For example NSE does not work with grepable. So you might want to use xml instead.

```
# To text-file
-oN nameOfFile

# To grepable format
-oG nameOfFile

# To xml
-oX nameOfFile
```

### Scan an entire IP-range

You might find that a site has several machines on the same ip-range. You can then use nmap to scan the whole range.

The `-sn` flag stops nmap from running port-scans. So it speeds up the process.

```
nmap -vvv -sn 201.210.67.0/24
```

You can also specify a specific range, like this

```
nmap -sP 201.210.67.0-100
`
```

#### Sort out the machines that are up

So let's say you find that 40 machine exists in that range. We can use grep to output those IP:s.

First let's find the IPs that were online. Ip-range is the output from previous command. You can of course combine them all.

```bash
cat ip-range.txt | grep -B 1 "Host is up"
```

Now let's sort out the ips from that file.

```bash
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' ip-range.txt > only-ip.txt
```

Now you can input all those ips to nmap and scan them.

#### Scan a range and output if a specific port is open

Nmap has a command to make the output grepable.

```bash
nmap -vvv -p 80 201.210.67.0-100 -oG - | grep 80/open
```

### Nmap scripts

This chapter could also be placed in Vulnerability-analysis and Exploitation. Because nmap scripting is a really versatile tool that can do many things. Here we will focus on it's ability to retrieve information that can be useful in the process to **find vulnerabilities**

First locate the nmap scripts. Nmap scripts end in `.nse`. For Nmap script engine.

```
locate *.nse
```

The syntax for running a script is:

```
nmap --script scriptname 192.168.1.101
```

To find the "man"-pages, the info about a script we write:

```
nmap -script-help http-vuln-cve2013-0156.nse
```

**Run multiple scripts**

Can be run by separating the script with a comma

```
nmap --script scriptone.nse,sciprt2.nse,script3.nse 192.168.1.101
```

Run the default scripts

```
nmap -sC example.com
```

## Metasploit

We can do port-scanning with metasploit and nmap. And we can even integrate nmap into metasploit. This might be a good way to keep your process neat and organized.

### db_nmap

You can run `db_nmap` and all the output will be stored in the metasploit database and available with

```
hosts
services
```

You can also import nmap scans. But you must first output it in xml-format with the following flag

```
nmap 192.168.1.107 -oX result.xml
```

Good practice would be to output the scan-results in xml, grepable and normal format. You do that with

```
nmap 192.168.1.107 -oA result
```

Then you can load it into the database with the following command.

```
db_import /path/to/file.xml
```

### Metasploit PortScan modules

If you for some reason don't have access to nmap you can run metasploits modules that does portscans

```
use auxiliary/scanner/portscan/
```

## Stealing Sensitive Information Disclosure from a Web

If at some point you find a **web page that presents you sensitive information based on your session**: Maybe it's reflecting cookies, or printing or CC details or any other sensitive information, you may try to steal it. Here I present you the main ways to can try to achieve it:

- [**CORS bypass**](https://book.hacktricks.xyz/pentesting-web/cors-bypass): If you can bypass CORS headers you will be able to steal the information performing Ajax request for a malicious page.
- [**XSS**](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting): If you find a XSS vulnerability on the page you may be able to abuse it to steal the information.
- [**Danging Markup**](https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection): If you cannot inject XSS tags you still may be able to steal the info using other regular HTML tags.
- [**Clickjaking**](https://book.hacktricks.xyz/pentesting-web/clickjacking): If there is no  protection against this attack, you may be able to trick the user into sending you the sensitive data (an example [here](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

## Exercise

This week we won't have CTF grades. But you still can have a try.

### (0 pt) Kitten War: Behind the Domain

Each year, those dragon-li cats would have a war with orange cats. From dining hall to library, from Lychee Hill to TB2. All day to night they fought together to claim manor.

However, this year things are different. Since the COVID-19 becomes serious and dangerous, which can also infect cats. Kitten war would be hold online.

Now, dragon-li cats just borrowed ours domain name to establish their website. Once the website is finished, they would hire too many cats that orange cats can't fight.

One day, when you step into TB2, an orange cat stopped you and begged, "humble human, please help us! We are losing the war."

![img](../assets/Week 4-11.jpg)

"Find out what are those dragon-li cats hiding. If you can retrieve the flag behind the domain, I would allow you to pat my belly - for 2 seconds!"

Kittens are so lovely, you can't resist and start to discover DNS records...

`compass.college`

*Hint1: cats like TXT because TXT looks so cute!*

*Hint2: cats only know a few words listed in the file below.*

[wordlist.txt](file/chall4-1.txt)

### (0 pt) Kitten War: 5 Cats in a Row

Two dragon-li cats are staring at you for a while, since the last cyber attack. After you step into the classroom in TB1, a dragon-li cat jumped on the desk and starts talking to you.

![img](../assets/Week 4-12.jpg)

"Orange cats are greedy. Team with us dragon-li cats." That cat licks its claw, said, "TB1 is ours manor, if you team with us, you can always pat cats in TB1."

"Now, here's your mission. Orange cats are using a website built by a CTFer from COMPASS. That guy is a noob and the website must be full of vulnerabilities. Check the sensitive files on the website and find us some flag."

"If we make orange cats have the website. They would be allowed to purchase dangerous weapons from online market. Then we won't defeat them in video games!"

Without a hesitate, you start to hack the website:

[Very cheap and nice weapons for orange cats :P)](http://103.102.44.218:10001/)

### (BONUS 0 pt) Kitten War: Black means Blind

The war has lasted for 2 months.

The dragon-li cats are settling in TB1 and dining hall, while the orange cats are claimed Lychee Hill and TB2.

A black cat was so struggle with these fights. The cat, said, "we, we are cats. We slept 20 hours a day. Why do we bother fighting instead of sleeping?"

![img](../assets/Week 4-13.jpg)

"Now you have a choice to stop the war," the black cat said, "everyone are looking at obvious things, but nobody cares about blind night."

"Log in COMPASS admin panel and use the final flag to stop the meaningless war."

[COMPASS Admin Note](http://103.102.44.218:10002/)

[app.py](file/chall4-3.py)

