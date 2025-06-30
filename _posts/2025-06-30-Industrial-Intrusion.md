---
title: "Tryhackme Industrial Intrusion"
date: 2025-06-30 01:09:33 +0300
author: [hushkat]
description: Tryhackme Industrial Intrusion Writeups
image: /assets/images/THM/Industrial_Intrusion.jpg
categories: [Web, Misc, B2R, Boot2Root, Easy, Tryhackme, THM, Forensics, ICS, Industrial Control Systems]
tags: [WEB, Cryptography, Easy, KenyaCyberlympics]
---

---
# Breach
## Challenge Overview

**Description:**

> This engagement aims to find a way to open the gate by bypassing the badge authentication system.
> The control infrastructure may hold a weakness: Dig in, explore, and see if you have what it takes to exploit it.
> Be sure to check all the open ports, you never know which one might be your way in!

**Target IP:** `10.10.123.189`

## Enumeration

I did an NMAP scan and these were the results:

```bash
sudo nmap -sV -T4 -p- 10.10.123.189
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-27 12:53 BST
NSOCK ERROR [161.2690s] mksock_bind_addr(): Bind to 0.0.0.0:111 failed (IOD #16): Address already in use (98)
Nmap scan report for ip-10-10-123-189.eu-west-1.compute.internal (10.10.123.189)
Host is up (0.00029s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http          Werkzeug/3.1.3 Python/3.12.3
102/tcp   open  iso-tsap      Siemens S7 PLC
502/tcp   open  mbap?
1880/tcp  open  vsat-control?
8080/tcp  open  http-proxy    Werkzeug/2.3.7 Python/3.12.3
44818/tcp open  EtherNetIP-2?
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
<=======================SNIP======================>
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.41 seconds
```
HTTP on port 80 and 8080 both running Werkzeug Python servers (versions 3.1.3 and 2.3.7 respectively). 
Werkzeug is a Python WSGI utility library often used with Flask apps, so these could be web applications worth exploring for vulnerabilities or misconfigurations.

Visiting port 80:
![Por80](/assets/images/THM/Breach/Port80.png)

Leveraging some online research, I learnt that there is a UI page for the service running on port 1880 which is Node-RED. On visiting the discovered UI endpoint, I changed the status of these switches:

![OT_Dashboard](/assets/images/THM/Breach/OT_dashboard.png)

That got me the Flag for this challenge:

![Flag](/assets/images/THM/Breach/Flag_Breach.png)

# Discord
## Challenge Overview

**Description:**

> Join our Discord server and find the flag?

### Step 1: Following the Trail from the Channel Description

The journey started in the `#industrial-intrusion-ctf` channel. While browsing through the channel list, I noticed something unusual in the **channel description**. As shown below, the description of the channel wasn’t just text — it included a **URL** ending with: `/secret-function` :

![DiscordTHM.png](/assets/images/THM/Discord/DiscordTHM.png)

### Step 2: Executing the Secret Function

After seeing the `/secret-function` clue, I suspected it might be a **custom slash command** integrated into the TryHackMe Discord bot. Discord supports slash commands which can be triggered by typing `/` followed by the command name.

So, I typed: `/secret-function` . 
As seen below, this triggered a response from the **TryHackMe bot** — and bingo! It revealed the flag:

![DiscordTHM.png](/assets/images/THM/Discord/DiscordFlag.png)
