---
title: inCTF - Writeup Foren Challenge
subtitle: I'm presenting to you the writeup of Digital Forensics from inCTF2021.

# Summary for listings and search engines
summary: I'm presenting to you the writeup of Digital Forensics from inCTF2021.
# Link this post with a project
projects: []

# Date published
date: "2021-08-15T00:00:00Z"

# Date updated
lastmod: "2021-08-153T00:00:00Z"

# Is this an unpublished draft?
draft: false

# Show this page in the Featured widget?
featured: false

# Featured image
# Place an image named `featured.jpg/png` in this page's folder and customize its options here.
image:
  caption: ''
  focal_point: ""
  placement: 2
  preview_only: false

authors:
- SemahBA

tags:
- CTF-Writeups
- inCTF

categories:
- Forensics

---
# inCTF

```
Title                      Category             Points        Flag
-------------------------- -------------------  ------- -----------------------------
Ermittlung                  Forensics             140     inctf{Outlook_Express_27-07-2020_12:26:17_4_6.0.2900.5512}

```

# Ermittlung


## TL;DR
Chat Application Used -> finding msimn.exe process

Last time the application was used -> userassist plugin and look for the binary

How many unread messages -> Registry HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UnreadMail\<email address>

Version -> Registry HKEY_CURRENT_USER\Software\Microsoft\Outlook Express\5.0\Shared Settings\Setup

## Challenge 

![](https://i.imgur.com/aEN08ni.png)

Starting by downloading the challenge file.
The first thing to do is identifying the operating system, so we are going to use ``imageinfo`` plugin.

`` vol.py -f ermittlung.raw imageinfo`` to get the Profile.

![](https://i.imgur.com/otEiXJL.png)

the profile is : ``WinXPSP2x86``

## What is the name of the chat application program? 

So we need to get the chat application. Checking the process, using the plugin ``pslist`` something interesting is present which is ``msimn.exe`` (msimn.exe is the executable for Microsoft Outlook Express).

![](https://i.imgur.com/egqkKp2.png)
 
Okay so we leave this answer here : 

``Chat Application -> Microsoft Outlook Express``

## When did the user last used this chat application?

using ``userassist`` plugin and look for ``msimn.exe``

``vol.py --plugins=~/Downloads/volatility/volatility/plugins --profile=WinXPSP2x86 -f ermittlung.raw userassist > userassist``

![](https://i.imgur.com/59jze4P.png)

Last used date : ``2020-07-27 12:26:17``

## How many unread messages are there in the chat application that the user is using?

After little googling about the unread mails, i found little [article](https://www.itprotoday.com/email-and-calendaring/how-can-i-reset-unread-email-counter-windows-xp-welcome-logon-screen)
that used the registry i need. 
``HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UnreadMail\<email address>``

we found the email address : 

![](https://i.imgur.com/Z2ed7ys.png)


``vol.py --plugins=~/Downloads/volatility/volatility/plugins --profile=WinXPSP2x86 -f ermittlung.raw printkey -o 0xe1aa5b60 -K 'Software\Microsoft\Windows\CurrentVersion\UnreadMail\danial.banjamin008@gmail.com'``

![](https://i.imgur.com/vpUG9TJ.png)

We get ``4`` unread mails.

## What is the current version of the chat application that's being used?

To get the application version, i digged in to the registries: 
``HKEY_CURRENT_USER\Software\Microsoft\Outlook Express\5.0\``

And followed all the subkeys present:
``vol.py --plugins=~/Downloads/volatility/volatility/plugins --profile=WinXPSP2x86 -f ermittlung.raw printkey -o 0xe1aa5b60 -K 'Software\Microsoft\Outlook Express\5.0\Shared Settings\Setup``

and we get : ``REG_SZ        MigToLWPVer     : (S) 6,0,2900,5512\u2018|``

So the version of the application was : ``6,0,2900,5512``

So following the flag format: The flag was :

``inctf{Outlook_Express_27-07-2020_12:26:17_4_6.0.2900.5512}``


