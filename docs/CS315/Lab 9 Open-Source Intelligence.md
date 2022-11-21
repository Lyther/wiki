# Lab 9: Open-Source Intelligence

> Reference: https://ctfacademy.github.io/osint/index.htm by CTF Academy
>
> Reference: https://osintframework.com/ by jnordine

![img](https://miro.medium.com/max/1050/1*15OCihvR_z3eHcD9b89JUw.jpeg)

## Open Source Intelligence

Open-source intelligence, also known as OSINT, refers to gathering information from publicly available sources, such as social media, company websites, and news articles. There is a great deal of information that can be gathered about a company or person through open-source intelligence.

### OSINT Techniques

In a cybersecurity context, OSINT can be used to recon a target before performing a [penetration test](https://ctfacademy.github.io/other/glossary.htm#penetrationtest) or to generate a report of the information a company is leaking through public sources. Cybercriminals use OSINT to collect information on a target before attacking; also, OSINT can be used to help guess a user’s password. Many people use passwords that relate to themselves. For example, a common password creation method is to use the name of your favorite pet followed by the year you were born. This is a very poor password creation technique because this information is easy for a [malicious](https://ctfacademy.github.io/other/glossary.htm#malicious) user to obtain from openly available sources, such as your social media accounts. In addition to possible password information, OSINT can reveal information about a company’s internal computer network. For example, a company’s promotional website may include pictures of employees working. These pictures may reveal information about the company’s inner workings, such as internal website URLs and private documents. OSINT can also be used to create a phony, malicious email targeting a company or individual; these phony emails are referred to as “phishing” emails.

### OSINT Attack Example

The following is an example of a company press release and a phishing email created using information from the press release:

```
Company XYZ

Recently Company XYZ has been making astounding progress on a new project. We have been working with many of the finest software engineers to develop a new internet browser with voice control capabilities. A special thanks go out to John Smith from Software ABC Corp. for his assistance with this project (more information can be found at softwareabccorp.com). The expected release date is early 2021.

Company XYZ,
Speaking is the future!
```

Using the information in the above press release, an attacker could form the following phishing email:

```
Email

To: ceo@companyxyz.com
From: jsmith@softwareabccorp.co
Subject: New Research About Voice Control

Dear Company XYZ CEO,

Here is a link to my new research paper about voice control technologies: Softwarecorp.co/newpaper.pdf.

Due to our recent collaboration on your new internet browser, I know this paper will interest you greatly. Please read it and give me your thoughts.



Thank you,
John Smith
Software ABC Corp.
```

The attacker would send the above email to the CEO in hopes she would click on the link and unknowingly download the attacker’s malicious file containing a computer virus.

The attacker created this email using information gleaned from Company XYZ’s press release. The attacker registered a website and email at “softwareabccorp.co,” notice the “.co” instead of the “.com” at the end of the address. Also, the name of the researcher connected to the project, John Smith, was mentioned in the press release and was used by the attacker to add believability to his phishing email. Finally, the attacker’s link to a supposed “research paper” that would be of interest to the targeted CEO. In a malicious phishing email, this link would lead to a computer virus and infect the CEO’s computer.

## OSINT Defensive Techniques

OSINT can also be used defensively. Open source intel can be used to keep up with cybersecurity trends and the techniques cyber criminals are using right now. Many websites provide OSINT about cyber attack trends reported by cybersecurity professionals. Also, when a company is receiving unusual internet traffic, OSINT can be used to determine if the usual traffic is coming from a known malicious IP address (An IP address is a four-part number that identifies the source of a network connection).

The following are just a few of the thousands of IP addresses that originate from China:

A cyber defender can better analyze unusual internet traffic using public sources about IP address origins.

For example, if the network administrator at an organization notices a high volume of internet traffic causing the organization’s website to be overloaded, he can analyze the origins of the internet traffic and determine if the traffic is likely malicious. Using OSINT to research the IP addresses of the internet traffic, a cybersecurity specialist can determine if the traffic originates from known malicious IP addresses.

| Chinese IP Addresses |
| -------------------- |
| 36.37.36.114         |
| 36.37.39.204         |
| 42.1.128.64          |

A cyber defender can better analyze unusual internet traffic using public sources about IP address origins.

For example, if the network administrator at an organization notices a high volume of internet traffic causing the organization’s website to be overloaded, he can analyze the origins of the internet traffic and determine if the traffic is likely malicious. Using OSINT to research the IP addresses of the internet traffic, a cybersecurity specialist can determine if the traffic originates from known malicious IP addresses.

## OSINT Framework

Visit [OSINT Framework](https://osintframework.com/) for OSINT structure and categories.

## Assignment

### (1 - Easy) Emo

In the circle of friends, I found a photo. There is more information than thought.

Flag format: flag{[from city]-[to city]-[flight number]}

For example: flag{深圳-广州-1A2345}

[Attachment](static/1.zip)

### (2 - Easy) Travel Photo

I want to travel here too! But how to find the location?

Flag format: flag{[city name]-[location name]}

For example: flag{深圳-欢乐谷}

[Attachment](static/2.zip)

### (3 - Medium) Home

A photo that was taken from someone's house. A lovely place to live in.

Flag format: flag{[location name]}

For example: flag{荔园}

[Attachment](static/3.zip)

### (4 - Medium) Football

A real fan can remember this immediately.

Flag format: flag{[yyyy-mm-dd]-[location name]}

For example: flag{2022-02-30-风雨操场}

[Attachment](static/4.zip)