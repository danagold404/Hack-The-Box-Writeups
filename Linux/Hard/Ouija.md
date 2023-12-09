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
