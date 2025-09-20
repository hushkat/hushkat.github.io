---
title: "RDP & Reconnaissance"
date: 2024-12-03T01:09:33+03:00
draft: false
description: "CyberGon CTF writeups covering threat intelligence and reconnaissance challenges"
slug: "rdp-reconnaissance"
tags: ["Reconnaissance", "ThreatIntelligence", "Easy", "CyberGonCTF"]
categories: ["CTF", "ThreatIntelligence"]
showAuthor: true
showDate: true
showReadingTime: true
showWordCount: true
featureimage: "https://ctftime.org/media/events/CYBERGON_Logo.png"
---

# RDP - TI

This was an interesting challenge on Threat Intelligence. I extracted most of the flag parts from [this](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/) website. 

## Instructions
Midnight Blizzard launched a spear-phishing campaign to distribute malicious RDP files. Are you familiar with the signature identified by Microsoft Defender for this campaign ? Additionally, do you know the number of well-known RDP files, number of the sender domain, and the APT designation associated with Midnight Blizzard ?

CYBERGON_CTF2024{Signature_XX_XX_APTXX}

Breaking the question into small parts, we have:

1. Are you familiar with the signature identified by Microsoft Defender for this campaign ?
From the website mentioned at the start of this blog, I found this:

![MSDefender](/images/CyberGon/DefenderSignature.png)
The signature therefore seems to be: `Backdoor:Script/HustleCon.A`

2. Do you know the number of well-known RDP files?
I also found the list of RDP files as shown below:

![RDPfiles](/images/CyberGon/RDP_files.png)
Counting from what has been listed here, we have a total of: `15`

3. Number of the sender domain?
I could also find the sender domains as shown below:
![Domains](/images/CyberGon/Domains.png)
We can count upto: `5`

4. The APT designation associated with Midnight Blizzard?
Looking at the [Mitre ATT&CK framework](https://attack.mitre.org/groups/G0016/)
![APT29](/images/CyberGon/APT29.png)

With what I have collected so far, the flag construction looks like this:
`CYBERGON_CTF2024{Backdoor:Script/HustleCon.A_15_05_APT29}`

# Secure Life - Reconnaissance

The instructions were simple:

What is the certificate's expiration date?

Flag Format - CYBERGON_CTF2024{YYYY:MM:DD:HH:MM:SS}

We were given [this](https://drive.google.com/file/d/1sRcUH_6uJKUP09difX1LLW4PIQ43Ub7z/view?usp=sharing) file. I first tried to look at the contents of the document and try to get the expiration date which was there, but then I couldn't see the specific time. So I tried to default to `00:00:00` When I submitted the flag, it failed and now I was just left with just one attempt. I therefore consulted with my friend chatGPT and he gave me this command that helped me retrieve the exact details I needed:

```
openssl x509 -inform DER -in certificate.der -noout -enddate
notAfter=Nov 24 20:38:00 2039 GMT
```
I therefore constructed the flag to look like so: `CYBERGON_CTF2024{2039:11:24:20:38:00}` and submitted it.

---
