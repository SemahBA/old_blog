---
title: Doctor HTB
summary: Walkthrough of a HTB Machine Doctor.
tags:
- HTB
date: "2016-04-27T00:00:00Z"

# Optional external URL for project (replaces project detail page).
external_link: ""

image:
  caption: Doctor HTB
  focal_point: Doctor

links:
- icon: twitter
  icon_pack: fab
  name: Follow
  url: https://twitter.com/BenaliSemah
url_code: ""
url_pdf: ""
url_slides: ""
url_video: ""

# Slides (optional).
#   Associate this project with Markdown slides.
#   Simply enter your slide deck's filename without extension.
#   E.g. `slides = "example-slides"` references `content/slides/example-slides.md`.
#   Otherwise, set `slides = ""`.
# slides: example
---
# Doctor : Linux Easy Machine

## Recon

**nmap**

From nmap scan we find 3 open ports

  ssh(22),http(80),HTTPS/Splunk (8089)

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-30 20:52 EST
Nmap scan report for doctor.htb (10.10.10.209)
Host is up (0.091s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.20 seconds
```

## Web application

Visiting the web page :

![](https://i.imgur.com/z1SaDz3.png)

Looking around, there is an email "info@doctors.htb"

so i added ``doctors.htb`` to hosts file

![](https://i.imgur.com/xuvZhqW.png)

I launched gobuster, and started looking around but no SQLi seemed to work, so i created an account.

**Gobuster found:**

```
/home (Status: 302)
/login (Status: 200)
/archive (Status: 200)
/register (Status: 200)
/account (Status: 302)
/logout (Status: 302)
```

**New message** tab creates a new message and display it in the home page: 
![](https://i.imgur.com/mnLtVbl.png)

After creating the new message, we check code source of /archive, we find : 

![](https://i.imgur.com/7PHbXt7.png)

Whatever I typed in the **New message title field** it gets reflected in the /archive page source.

**We know it's vulnerable to** [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) ,  but we don’t know which template is being used here

 ### Identifying The Template
 
 ![](https://i.imgur.com/VLuCM1c.png)
 
 Following the image , we get it's either Jinja2 or Twig. 

## Gaining Reverse Shell

I uploaded a bash script, prepared my listener, and executed the script 

![](https://i.imgur.com/bivM64q.png)

## Enumeration 

Launching Linpeas script, in ``Finding passwords inside logs`` we find : 
**POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"**

Switching from web user to shaun, and we get user.txt

![](https://i.imgur.com/ZP7dSjU.png)

## Privilege Escalation

Going back to the open Port (HTTPS/Splunk (8089)), there is an interesting blog showing how to [abuse the splunk](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)

Following the Blog , and since we have user shaun his password Guitar123. I launched the script with the necessary parameters and started listener : 

![](https://i.imgur.com/JhSFLk9.png)

After executing the exploit, we get a connection 

![](https://i.imgur.com/9ZpiCAF.png)


I had fun solving this machine, Shout out to the creator [egotisticalSW](https://www.hackthebox.eu/home/users/profile/94858). Hope you enjoyed the walkthrough.
Peace.
