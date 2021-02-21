---
title: SecurinetsMINICTF - Writeups of my challenges
subtitle: I'm presenting to you the writeups of the challenges i managed to create during SecurinetsMINICTF.

# Summary for listings and search engines
summary: I'm presenting to you the writeups of the challenges i managed to create during SecurinetsMINICTF.
# Link this post with a project
projects: []

# Date published
date: "2021-02-20T00:00:00Z"

# Date updated
lastmod: "2021-02-203T00:00:00Z"

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
- SecurinetsMINI

categories:
- Forensics

---
# SecurinetsMINICTF

```
Title                      Category             Points        Flag
-------------------------- -------------------  ------- -----------------------------
Memory 1                    Forensics             496     Securinets{Semah_P@ssword123_Win7SP1x64}
Memory 2                    Forensics             499     Securinets{Verrati_is_proud_of_you!}
Foxyy News                  Forensics             500     Securinets{not_bad_for_now_but_you_made_it_this_far_so_well_done_im_proud}
```

# Memory 1

![](https://i.imgur.com/Jb4wbZS.jpeg)

Starting by downloading the challenge file. The first challenge asking for username,password and profile
`` vol.py -f memdump.raw --imageinfo`` to get the image info.

for the user and password , you can mimikatz plugin or hashdump and crack the hash using crackstation

**flag :Securinets{Semah_P@ssword123_Win7SP1x64}**

# Memory 2

![](https://i.imgur.com/Dg77ZF5.jpeg)

So from the descrtion we need to find a key, which not stored in a typical file and there 'nerd'. we will be back to that later.

checking **cmdscan** we find some intresting stuff : 

![](https://imgur.com/sk8z0jt.png) 


Dumping the secret.py ``vol.py -f memdump.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007e2bef20 -D . ``

```python
#!/usr/bin/python

import sys, getopt
from Crypto.Cipher import AES
import random
from base64 import b64encode,b64decode

def pad(msg):
    c = 16-len(msg)%16
    return msg + chr(c)*c

def encrypt_file(inp_f,out_f,key):
   k = random.seed(key)
   kk = []
   for i in range(16):
      kk.append(random.randint(96,126))
   random.shuffle(kk)
   new_key = ''.join([chr(j) for j in kk])
   cipher = AES.new(new_key, AES.MODE_ECB)
   inp = open(inp_f,'rb').read()
   enc = cipher.encrypt(pad(inp))
   g = open(out_f,'w').write(enc)

def main(argv):
   inputfile = ''
   outputfile = ''
   key=''
   try:
      opts, args = getopt.getopt(argv,"hi:o:k",["help","ifile=","ofile=","key="])
   except getopt.GetoptError:
      print 'usage : secure.py -i <inputfile> -o <outputfile> -k <key>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'secure.py -i <inputfile> -o <outputfile> -k <key>'
         sys.exit()  
      elif opt in ("-i", "--ifile"):
         inputfile = arg
      elif opt in ("-o", "--ofile"):
         outputfile = arg
      key = sys.argv[6]
   encrypt_file(inputfile,outputfile,key)
   print ("successfully encrypted !! ")

if __name__ == "__main__":
   if len(sys.argv)<7:
      print ('usage : secure.py -i <inputfile> -o <outputfile> -k <key>')
      exit(0)
   main(sys.argv[1:])
```

from the cmdscan and the script, we have the key "super_secure_key" and the encrypted.txt provided in the description which is base64encoded.

it's easy to decrypt it. seeding with the key(which we have) and simple AES decryption 

decyrpting part : 

```python
#!/usr/bin/python

import sys, getopt
from Crypto.Cipher import AES
import random
from base64 import b64encode,b64decode

def pad(msg):
    c = 16-len(msg)%16
    return msg + chr(c)*c

def decrypt_file(inp_f,out_f,key):
   k = random.seed(key)
   kk = []
   for i in range(16):
      kk.append(random.randint(96,126))
   random.shuffle(kk)
   new_key = ''.join([chr(j) for j in kk])
   cipher = AES.new(new_key, AES.MODE_ECB)
   inp = open(inp_f,'rb').read()
   dec = cipher.decrypt(b64decode(inp))
   g = open(out_f,'w').write(dec)

def main(argv):
   inputfile = ''
   outputfile = ''
   key=''
   try:
      opts, args = getopt.getopt(argv,"hi:o:k",["help","ifile=","ofile=","key="])
   except getopt.GetoptError:
      print 'usage : secure.py -i <inputfile> -o <outputfile> -k <key>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'secure.py -i <inputfile> -o <outputfile> -k <key>'
         sys.exit()  
      elif opt in ("-i", "--ifile"):
         inputfile = arg
      elif opt in ("-o", "--ofile"):
         outputfile = arg
      key = sys.argv[6]
   decrypt_file(inputfile,outputfile,key)
   print ("successfully decrypted !! ")

if __name__ == "__main__":
   if len(sys.argv)<7:
      print ('usage : secure.py -i <inputfile> -o <outputfile> -k <key>')
      exit(0)
   main(sys.argv[1:])
```

![](https://imgur.com/3UWHQbw.png) 

We got a drive link : https://drive.google.com/file/d/1D26z9O98fdXo_HdCTsZ0GyAvM2DNChfY/view?usp=sharing

Downloading the file and we got a Secret file. From the Description Vera and Crypto, it's **Veracrypt** . But we need the password.Trying the key from the script didn't work
, the password of the user also didn't work.
Backing to 'nerd' Part ! nerd and not typical files .
Let's dig in the registries. 

![](https://imgur.com/Mw8aSRf.png) 

![](https://imgur.com/MGkmtVs.png) 

there is **PwdAndKey** , checking it and we get : 

![](https://imgur.com/pv8Adqz.png)

nice we got a key : ``the_best_place_to_hide_my_pwd_and_keeeeeeeeeey``

mounting the image providing the key 

![](https://i.imgur.com/8px1d8b.jpg) 

and we get : 

![](https://i.imgur.com/3FuSYaO.jpg)

There is many messages in files, try enable view hidden files, we get a hidden file in the Desktop folder ``gift.txt`` : 

![](https://i.imgur.com/dUEfUjZ.jpg)

**Flag : Securinets{Verrati_is_proud_of_you!}**



# Foxyy News!

![](https://i.imgur.com/x3LwtAV.jpg)

It's a disk image, Using Autopsy or FTK Image :

![](https://i.imgur.com/zw9EM4I.jpg)

checking the recycle bin, there is a deleted file which has : 

![](https://i.imgur.com/6ci3HYt.jpg)

Okey, all dev and talking about updating the website and removing the added string which not yet deleted. Looking around, we find the website folder 

``/Users/Semah/Documents/website_folder/``

So checking the index.html looking for the added strings which not been deleted yet, we find in the index.html , a comment string : 

![](https://i.imgur.com/RGOtOw7.jpg)

So MasterPasswd? a Master Password : ``isSemahDoingfinesofar?``

It's related to Firefox password Manager ! Firefox saves **the saved passwords** in key4.db

So extracting ``/Users/Semah/Appdata/Roaming/Mozilla/Firefox/Profiles/7f5mo1k4.default-release/`` 

To decrypt it and extract the saved password, simple google search leads to tool [firepwd](https://github.com/lclevy/firepwd), 
we get the mail and password of the gmail account : 

```
	user : SemaSecurinets@gmail.com 
	password :firstpartflag:not_bad_for_now
```

**first part of the flag : Securinets{not_bad_for_now**

Going to gmail : we read the email 

![](https://i.imgur.com/bZZT3h0.jpg)

Don't use the same password ?? Okey so he used the some password somewhere else. Backing to Autopsy, and keep digging , we find **Secret.kdbx** under **/Users/Semah/Save Games/**
It's keepass file!

open it with Keepass using gmail password :

![](https://i.imgur.com/2wmG5Y1.jpg)

we find : 

![](https://i.imgur.com/IJ7A8eb.jpg)

the password in the important is a imgur link : https://i.imgur.com/6vfWdGj.png 

which is the second part of the flag : **but_you_made_it_this_far_so_well_done_im_proud}**

**Flag : Securinets{not_bad_for_now_but_you_made_it_this_far_so_well_done_im_proud}**







