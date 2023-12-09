**Disclaimer:** In this box I only got to the user flag because the path to root was based on reverse engineering using Ghidra, which I haven't learned yet.

# STEP 1 - Initial Enumeration
I started of with a full Nmap scan using NmapAutomator.

```
./nmapAutomator.sh -H <TARGET IP> -t All
```

## Ports and Services
|    **Service**    |     **Port**      |    **Version**    |
|-------------------|-------------------|-------------------|
|         SSH          |          22/tcp         |OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)|
|         HTTP          |         80/tcp          |Apache httpd 2.4.52|
|         HTTP          |         3000/tcp          |Node.js Express framework|


