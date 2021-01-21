---
title: FwordCTF2020 - Writeups of my challenges
subtitle: I'm presenting to you the writeups of the challenges i managed to create during FwordCTF2020.

# Summary for listings and search engines
summary: I'm presenting to you the writeups of the challenges i managed to create during FwordCTF2020.
# Link this post with a project
projects: []

# Date published
date: "2021-01-19T00:00:00Z"

# Date updated
lastmod: "2021-01-193T00:00:00Z"

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
- Cryptography
- Forensics
- Reverse Engineering
- Misc
---
# FwordCTF2020

```
Title                      Category             Points  Flag
-------------------------- -------------------  ------- -----------------------------
BG&BD!                    Cryptography           496     FwordCTF{boneh_and_blum?_mix3d_but_good_j0b!!}
Schuuuuush                Cryptography           499     FwordCTF{Mehdi_knows_alot_about_Schmidt-samoa_but_is_it_better_than_RSA?}
ShameOnMe!                Cryptography           500     FwordCTF{shame_on_shamir_he_deserves_walk_of_shame}
MiniCopper?               Cryptography           498     FwordCTF{I_dont_know_what_i_was_thinking_about_doing_this}
OnePart!                  Cryptography           261     FwordCTF{i_knew_it_its_not_secure_as_i_thought}
XO                        Reverse Engineering    475     FwordCTF{NuL1_Byt35?15_IT_the_END?Why_i_c4nT_h4ndl3_That!}
TwisTwisLitlleStar        Misc                   470     FwordCTF{R4nd0m_isnT_R4nd0m_4ft3r_4LL_!_Everyhthing_is_predict4bl3_1f_y0u_kn0w_wh4t_Y0u_d01nGGGG}
Repeat                    Misc                   493     FwordCTF{repetition_code_is_the_way_to_send_a_message_without_corruption}
Infection                 Forensics(DiskImage)   498     FwordCTF{32d6c684f1e93d0ba67d4c865f1f757f}
```

# BG & BD ! |Cryptography : 496pts

_**Description :**_ 

Best Gift and Best Day !

Author: Semah BA

[Challenge file ](BGBD.py)

## TL;DR:
  1. e,n ~length, use wiener attack and decrypt the first part
  2. from wiener we can extract the primes to use for the second part
  3. Second part: Blum goldwasser
  
## Overview
### Startring with the first part : 
Let's focus on enc1 which is simple RSA encryption. We have e and n ~ same length  which is exposed to wiener attack.
For this purpose, applying the Wiener continued fraction attack :
1. We try to find the continued fractions expansion of e/N
2. Converts a rational x/y fraction into a list of partial quotients [a0, ..., an]
3. Computes the list of convergents using the list of partial quotients
4. For each convergent, we check if d is actually the key, check if the equation x^2 - s*x + n = 0  has integer roots with s = n-phi+1

Code : 
```python
#!/usr/bin/python  

def rational_to_contfrac(x,y):
  a = x//y
  pquotients = [a]
  while a * y != x:
    x,y = y,x-a*y
    a = x//y
    pquotients.append(a)
  return pquotients

def contfrac_to_rational (frac):
  if len(frac) == 0:
      return (0,1)
  num = frac[-1]
  denom = 1
  for _ in range(-2,-len(frac)-1,-1):
      num, denom = frac[_]*num+denom, num
  return (num,denom)

def convergents_from_contfrac(frac):
  convs = [];
  for i in range(len(frac)):
    convs.append(contfrac_to_rational(frac[0:i]))
  return convs

def isqrt(n):
  if n < 0:
      raise ValueError('square root not defined for negative numbers')
  if n == 0:
      return 0
  a, b = divmod(bitlength(n), 2)
  x = 2**(a+b)
  while True:
      y = (x + n//x)//2
      if y >= x:
          return x
      x = y

def bitlength(x):
  assert x >= 0
  n = 0
  while x > 0:
      n = n+1
      x = x>>1
  return n

def is_perfect_square(n):
  h = n & 0xF
  if h > 9:
      return -1
  if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
      t = isqrt(n)
      if t*t == n:
          return t
      else:
          return -1
  return -1

def break_it(e,n):  
  print "[+] Wiener attack in progress..."  
  frac = rational_to_contfrac(e, n)  
  convergents = convergents_from_contfrac(frac)  
  for (k,d) in convergents:  
    #check if d is actually the key  
    if k!=0 and (e*d-1)%k == 0:  
      phi = (e*d-1)//k 
      s = n - phi + 1  
      # check if the equation x^2 - s*x + n = 0  
      # has integer roots  
      discr = s*s - 4*n  
      if(discr>=0):  
        t = is_perfect_square(discr)  
        if t!=-1 and (s+t)%2==0:  
          print ("the value of phi : "+str(phi)) 
          return "the value of d : "+str(d)  

n=136925867715334350539351541819374303153581861883077425871381479619256902280896182751175418274848819117804106313526390171733172646719203781502341411544996240718046559322020330755493739123717974336861438650061159088512867158495809372652057009979517497499951599965613535967213529497308200114836792389883404448987
e=17742461742896634972201474241931685701682825423273435469196581493593083245061146905518481601646582623355393811189032402488804067701439209191772750727581718922909269638936474927145555944487152988216781157681122522177270474504549932191814852246849976334482284151493985991827502940015843682072459462031659332887
print (break_it(e,n))
```
simple RSA decryption : m=pow(c,d,n) , we get the first part of the flag : **well its not a long story to be told , you are on the right path , after darkness you find** 

### Jumping to the second part : 
```python
def encode(msg):
	enc_msg=""
	for i in msg:
		enc_msg+=bin(ord(i))[2:].zfill(8)
	return enc_msg

def enc2(msg,bs,mds):
	while len(msg)%bs!=0:
		msg='0'+msg
	ll=len(msg)/bs
	r=3945132
	x=pow(r,2,mds)
	c = ''
	for i in range(ll):
		x=pow(x,2,mds)
		p=(bin(x)[2:])[-bs:]
		c_i=int(p,2)^int(msg[i*bs:(i+1)*bs],2)
		ci_bin = format(c_i, '0' + str(bs) + 'b')
		c+=ci_bin
	return c,pow(x,2,mds)
  ```
  
  It's [Blum Goldwasser](https://en.wikipedia.org/wiki/Blum%E2%80%93Goldwasser_cryptosystem). But before starting decrypting, we need to retrieve the values of p2 and q2.  
Since we got phi and we have n it's now easy get p1,q1 which it leads to p2 and q2.  
**retrieving p1 and q1 from n and phi**

n = p*q

phi = (p-1)*(q-1) = n - p - q -1  => p + q = n - phi + 1 let's call this s

Now recall that in a quadratic equation : x**2 - sx  + prod = 0

```python
from sympy import * 
n  = 
phi = 
x = var('x')
p,q = solve(x**2-s*x+n)
``` 

Back to Blum Goldwasser, following wikipedia decryption part : 

![](https://i.imgur.com/WLH2VRi.png) 

```python
from Crypto.Util.number import *
import math
from sympy import lcm 
import random
from fractions import gcd 
from sympy import nextprime
from pwn import xor

def verify_keys(a,b):
	while True:
		if a%4==3:
			while b%4!=3:
				b=nextprime(b)
			return a,b
		if b%4==3:
			while a%4!=3:
				a=nextprime(a)
			return a,b
		a,b=nextprime(a),nextprime(b)

def xgcd(a, b):
	x0, x1, y0, y1 = 0, 1, 1, 0
	while a != 0:
		(q, a), b = divmod(b, a), a
		y0, y1 = y1, y0 - q * y1
		x0, x1 = x1, x0 - q * x1
	return b, x0, y0

def dec2(p,q,x,c,bs):
	nn=p*q
	t=len(c)/bs
	dp=pow((p+1)/4,82,p-1)
	dq=pow((q+1)/4,82,q-1)

	up=pow(x,dp,p)
	uq=pow(x,dq,q)
	_,rp,rq=xgcd(p,q)
	x0=(uq*rp*p+up*rq*q)%(p*q)
	xi=x0
	m=''
	for i in range(t):
		ci=c[i*bs:(i+1)*bs]
		xi=(xi**2)%nn
		xi_bin=bin(xi)
		pi=xi_bin[-bs:]
		ci_int = int(ci,2)
		pi_int = int(pi,2)
		mi = pi_int ^ ci_int
		mi_bin = format(mi, '0' + str(bs) + 'b')
		m+=mi_bin

	return m
cipher2,xt = '101110100011010000110010100100000011001110110001010101100101000000100111011010010010110101000101000110000100011001001100111011111011101001110111100001100011101010101111101100001000010111111000110110110010110100000001001011100010011000110100111100001100111001101110001111001100010001001111100110110110100001011100011100110101001000011100100011011110011000010100110010100111000010101101110101011100010110000100001101101101001111000101011100101100100110110011101000100010101000010001010010110110101011111101110011101110010000101001000111000000100100001010110111001011110001010100100001101111010010111101111001001001111010001100000111000010000100110101100010001111100011111100100100001010010100111010100010000101110000110101000101100', 99938901144293305318474508248429453175561082362898230514299720558762394911631823304146558717537729838080951066313213321374755623652896593453644503184122276925455269140340267427068200657877772040554093186417385902385500879519631051754226252925525926019109245833691317900888626583890623823019289563531254979763
p_1=11391686090403905599695015583829755003551766728158057028281938682097322841603835874354540607209988671617182359012432600907514677996087087987893334356043831
q_1=12019806956467800913778611206246062087922374347970383926984004278168670921911203657163080865199043522716298571169006826814578568813815787765574990776254077
p_2,q_2=verify_keys(p_1,q_1)
N=p_2*q_2
block_size=int((math.log(int(math.log(N,2)),2)))
dec=dec2(p_2,q_2,xt,cipher2,block_size)[1:]

flag=""
try:
	for i in range(len(dec)):
		flag+=chr(int(dec[i*8:(i+1)*8],2))
except:
	print (flag)
```
Second part of the message : the fire to light up your way ! your fire is FwordCTF{boneh_and_blum?_mix3d_but_good_j0b!!}

Full message : ***well its not a long story to be told , you are on the right path , after darkness you find the fire to light up your way ! your fire is FwordCTF{boneh_and_blum?_mix3d_but_good_j0b!!}"***

***flag : FwordCTF{boneh_and_blum?_mix3d_but_good_j0b!!}***


# Schuuuuush |Cryptography : 499pts

_**Description :**_

Mehdi doesn't like RSA that much, he loves playing around to prove that there is better things than RSA.Is it True?

Author: SemahBA

Source Code : 

```python
from Crypto.Util.number import getPrime, bytes_to_long
from gmpy2 import gcd
from sympy import nextprime
from secret import flag,BITS

func = lambda x, bits : x**12 + (x & (2**(bits/2)-1))

def PrimeGen(bits):
	pr = getPrime(bits)
	p = nextprime(func(pr,bits))
	qr = getPrime(bits)
	q = nextprime(func(qr,bits))
	return p, q	 

p,q = PrimeGen(BITS)
n = pow(p,2)*q
c = pow(bytes_to_long(flag),n,n)
```

output.txt :

```
{n:12838608941410176012340339820403664970195097778934681712442256463398083779434726523727337362548077816498494779634767166505330187300918251880884095061402948317273750734359805972172291702330170769941722135721254301797373910929209389934028023681108705224982459292501258476944977718620453591356928959990356039307404842140809349783009344965382885388230201854950013659777184155467116001057622057495928115145173039957373456282486463372004327112269636005406697476348929483659820840611834738925620510057932617464105487439853704904186236400811201279769590508776546485548532642090814468965154747150494170880560045656388451020601,c:7050573356706442469683539123500770567737718645915519903139491762612445024317075069313476689401710155602518263519640817376340655413504872884207299668765616582487443371872620836280094522785104280556591702549809637571584448052503290838137680131373345867011613789868193526268278698789425705452031352784824472345055152400817574925351780178219492978046243297746285248144022980576645706737451329739930693946984047194996318634833190911615115111633867444659880674198115147887713534332191601313998075654936972222500960455343228277446386199666597757275851736103707318615905859809209855195657904316567873616670459334137634275173}
```
### Encryption process : 

1. Generating primes p,q
2. n = pow(p,2)*q
3. cipher = pow(m,n,n)

It's [Schmidt-Samoa cryptosystem](https://en.wikipedia.org/wiki/Schmidt-Samoa_cryptosystem) 

We start by retrieving the value of BITS. Bit length of n is 2047 and n is effectively x^36. So bit length of x should be around (2047/36)±1.

p = a\**12+k1

q =  b\**12+k2

Analyzing the 12th root of n gives us : iroot(n,12)=a^2*b  

12th root of n gives us : 2199766062441797577302949884026507797060867827397893

using [factordb](http://factordb.com/) we get : 2199766062441797577302949884026507797060867827397893 = 1327888974003650812 * 124753565845126613 

that's **a and b**

### Decryption Process : 


![](https://i.imgur.com/bFPoYQq.png)

Solver script based on the image above : 

```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot
from sympy import invert, nextprime,lcm

n = 12838608941410176012340339820403664970195097778934681712442256463398083779434726523727337362548077816498494779634767166505330187300918251880884095061402948317273750734359805972172291702330170769941722135721254301797373910929209389934028023681108705224982459292501258476944977718620453591356928959990356039307404842140809349783009344965382885388230201854950013659777184155467116001057622057495928115145173039957373456282486463372004327112269636005406697476348929483659820840611834738925620510057932617464105487439853704904186236400811201279769590508776546485548532642090814468965154747150494170880560045656388451020601
c = 7050573356706442469683539123500770567737718645915519903139491762612445024317075069313476689401710155602518263519640817376340655413504872884207299668765616582487443371872620836280094522785104280556591702549809637571584448052503290838137680131373345867011613789868193526268278698789425705452031352784824472345055152400817574925351780178219492978046243297746285248144022980576645706737451329739930693946984047194996318634833190911615115111633867444659880674198115147887713534332191601313998075654936972222500960455343228277446386199666597757275851736103707318615905859809209855195657904316567873616670459334137634275173


appn = iroot(n,12)
print (appn)
#prime factor it to get pr and qr
pr = 124753565845126613

qr = 132788897400365081

for bits in range(55,59):
	p = nextprime(pr**12 + (pr & (2**(bits/2)-1)))
	q = nextprime(qr**12 + (qr & (2**(bits/2)-1)))
	l = lcm(p-1,q-1)
	try:
		d = invert(n,l)
		flag = long_to_bytes(pow(c,int(d),p*q))
		if "FwordCTF{" in flag:
			print flag
			break
	except Exception:
		continue
 ```
 
 ***flag : FwordCTF{Mehdi_knows_alot_about_Schmidt-samoa_but_is_it_better_than_RSA?}***




