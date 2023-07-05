---
title: ImaginaryCTF round 24
date: 2022-08-01 23:00:00 
categories: [ImaginaryCTF, round 24]
tags: [imaginaryctf] # TAG names should always be lowercase 
author: d3bug 
---
The challenges can be found at [https://imaginaryctf.org/ArchivedChallenges](https://imaginaryctf.org/ArchivedChallenges)

# Misc

## Pickle
**Description**
>This pickle seems to be hiding the flag...

**Attachments**
[https://imaginaryctf.org/f/1O5dx](https://imaginaryctf.org/f/1O5dx)

### Solution
Pickle can be decompiled with [Fickling](https://github.com/trailofbits/fickling)
output from `fickling`
```bash
❯ python -m fickling out.pickle
from __main__ import FlagPrinter
_var0 = FlagPrinter()
_var0.__setstate__({'flag': [105, 99, 116, 102, 123, 99, 117, 99, 117, 109, 98, 101, 114, 115, 95, 111, 114, 95, 112, 105, 99, 107, 108, 101, 115, 63, 125], 'fake': 'jctf{c0uld_th1s_b3_th3_fl4g?}'})
result = _var0
```
flag is a list with `ascii` values now, we can get the flag from the below python code 
```python
flag = [105,  99 ,116,102,123,99 ,117,99 ,117,109,98 ,101,114,115,95 ,111,114,95 ,112,105,99 ,107,108,101,115,63 ,125]

for i in  flag:
    print(chr(i),end="")

```
Flag: `ictf{cucumbers_or_pickles?}`

---

## TARp
**Description**
>It helps to have a rain tarp when there's bad weather.

**Attachments**
[https://imaginaryctf.org/f/tiUxj#server.py](https://imaginaryctf.org/f/tiUxj#server.py)

### Solution
it is a service that can unTAR files and read the extracted files 
i found that symlinks can be used to read or write files outside the extracted folder 
[https://github.com/cwgem/python-safe-tar-extract](https://github.com/cwgem/python-safe-tar-extract)
then created a tar that points to the `flag.txt` 
supplying the tar file we get the file

Flag: `ictf{is_it_still_a_zip_slip_if_we_use_a_tar_file?}`

---

# Forensics

## Lost flag 
**Description**
>Quasar said he lost his flag but it seems to me like it's in this file

**Attachments**
[https://imaginaryctf.org/f/fOweJ#flag.zip](https://imaginaryctf.org/f/fOweJ#flag.zip)

### Solution
running strings on the `./flag/.DS_store` we get the flag 
```bash
❯ strings -e b -n 6 .DS_Store
flag.jpg
!ictf{mac_is_better_than_templeos}
```
`-e b` specifies the 16-bit bigendian encoding([man page](https://www.man7.org/linux/man-pages/man1/strings.1.html))  
there are also online [parsers](https://labs.internetwache.org/ds_store/) for `.DS_store`
files 

Flag: `ictf{mac_is_better_than_templeos}`

----

## Age

**Description**
>Some things, despite appearing quite new, are actually rather old. Did you know python has been around for more than 30 years?


**Attachments**
[https://imaginaryctf.org/f/T2F1K#outer.py](https://imaginaryctf.org/f/T2F1K#outer.py)

### Solution
>`.pyc`  is the compiled bytecode,the internal representation of a Python program in the CPython interpreter

I was not able to find a `pyc` decompiler or parser for 3.10 so I dug in the source code and found the structure of pyc files 
```python
#https://github.com/python/cpython/blob/7e7a570818a41df6e97e25989d92449c7cc40aad/Lib/importlib/_bootstrap_external.py#L683

def _code_to_timestamp_pyc(code, mtime=0, source_size=0):
"Produce the data for a timestamp-based pyc."
data = bytearray(MAGIC_NUMBER)
data.extend(_pack_uint32(0))
data.extend(_pack_uint32(mtime))
data.extend(_pack_uint32(source_size))
data.extend(marshal.dumps(code))
return data
```
we have starting 16 bytes containg 
1. `MAGIC_NUMBER`
2. `0`
3. `unix_timestamp`
4. `source_size`

and the rest is `marshal` dump of the code
we can disassemble the the pyc with the following code
```python
import dis
import marshal
import struct
with open('./outer/gen.cpython-310.pyc','rb') as f:
	a = f.read(16)
	b = f.read()
header = struct.unpack('<4sLLL',a)
print(header)
code = marshal.loads(b)
print(dis.disassemble(code))
```
output:

```python
(b'o\r\r\n', 0, 667044855, 449)
  3           0 LOAD_CONST               0 (0)
              2 LOAD_CONST               1 (('ZipFile',))
              4 IMPORT_NAME              0 (zipfile)
              6 IMPORT_FROM              1 (ZipFile)
              8 STORE_NAME               1 (ZipFile)
             10 POP_TOP

  4          12 LOAD_CONST               0 (0)
             14 LOAD_CONST               2 (('sha256',))
             16 IMPORT_NAME              2 (hashlib)
             18 IMPORT_FROM              3 (sha256)
             20 STORE_NAME               3 (sha256)
             22 POP_TOP

  5          24 LOAD_CONST               0 (0)
             26 LOAD_CONST               3 (('time',))
             28 IMPORT_NAME              4 (time)
             30 IMPORT_FROM              4 (time)
             32 STORE_NAME               4 (time)
             34 POP_TOP

  6          36 LOAD_CONST               0 (0)
             38 LOAD_CONST               4 (('system',))
             40 IMPORT_NAME              5 (os)
             42 IMPORT_FROM              6 (system)
             44 STORE_NAME               6 (system)
             46 POP_TOP

  8          48 LOAD_NAME                7 (int)
             50 LOAD_NAME                4 (time)
             52 CALL_FUNCTION            0
             54 CALL_FUNCTION            1
             56 STORE_NAME               8 (unixtime)

  9          58 LOAD_NAME                3 (sha256)
             60 LOAD_NAME                9 (str)
             62 LOAD_NAME                8 (unixtime)
             64 CALL_FUNCTION            1
             66 LOAD_METHOD             10 (encode)
             68 CALL_METHOD              0
             70 CALL_FUNCTION            1
             72 LOAD_METHOD             11 (hexdigest)
             74 CALL_METHOD              0
             76 STORE_NAME              12 (password)

 10          78 LOAD_NAME               13 (print)
             80 LOAD_CONST               5 ('Writing with time')
             82 LOAD_NAME                8 (unixtime)
             84 LOAD_CONST               6 ('and password')
             86 LOAD_NAME               12 (password)
             88 CALL_FUNCTION            4
             90 POP_TOP

 11          92 LOAD_NAME                6 (system)
             94 LOAD_CONST               7 ('zip --password ')
             96 LOAD_NAME               12 (password)
             98 FORMAT_VALUE             0
            100 LOAD_CONST               8 (' inner.zip flag.txt')
            102 BUILD_STRING             3
            104 CALL_FUNCTION            1
            106 POP_TOP

 13         108 LOAD_NAME                1 (ZipFile)
            110 LOAD_CONST               9 ('outer.zip')
            112 LOAD_CONST              10 ('w')
            114 LOAD_CONST              11 (('mode',))
            116 CALL_FUNCTION_KW         2
            118 SETUP_WITH              24 (to 168)
            120 STORE_NAME              14 (outer_zip)

 14         122 LOAD_NAME               14 (outer_zip)
            124 LOAD_METHOD             15 (write)
            126 LOAD_CONST              12 ('inner.zip')
            128 CALL_METHOD              1
            130 POP_TOP

 15         132 LOAD_NAME               14 (outer_zip)
            134 LOAD_METHOD             15 (write)
            136 LOAD_NAME               16 (__file__)
            138 LOAD_METHOD             17 (split)
            140 LOAD_CONST              13 ('/')
            142 CALL_METHOD              1
            144 LOAD_CONST              14 (-1)
            146 BINARY_SUBSCR
            148 CALL_METHOD              1
            150 POP_TOP
            152 POP_BLOCK

 13         154 LOAD_CONST              15 (None)
            156 DUP_TOP
            158 DUP_TOP
            160 CALL_FUNCTION            3
            162 POP_TOP
            164 LOAD_CONST              15 (None)
            166 RETURN_VALUE
        >>  168 WITH_EXCEPT_START
            170 POP_JUMP_IF_TRUE        87 (to 174)
            172 RERAISE                  1
        >>  174 POP_TOP
            176 POP_TOP
            178 POP_TOP
            180 POP_EXCEPT
            182 POP_TOP
            184 LOAD_CONST              15 (None)
            186 RETURN_VALUE
None
```
from the disassembly we can see that the passwd for the `innner.zip` is `sha256(unix_timestamp)` 
i tried passwd around the the `timestamp` and found  the right timestamp as  `667044877`.\
decrypting with `ba2fe6b52f7610a6ddc4ce405d302e0eb93223b3b0c4d833895fe3ae68f0c0fe`
we get the flag

Flag: `ictf{i've_traveled_here_from_decades_ago_to_deliver_you_this_flag}`

---

## Geoguessr Sucks
**Description**
>I went on a crazy vacation to the middle of nowhere, and I took a real picture with real camera of this very important field. Where is it?
>
>Flag format is ictf{lat_long}, both rounded up to 5 decimal places because this exact spot is very important to me. Example: ictf{1.23456_7.89101} 

**Attachments**
[https://imaginaryctf.org/f/1OD91](https://imaginaryctf.org/f/1OD91 "https://imaginaryctf.org/f/1OD91")

### Solution
Running exiftool on the png we get the GPS coordinate
```
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Position                    : 39 deg 8' 1.31", 98 deg 31' 42.01"
```
we can convert the `DMS` to `DD` with online convertors like [this](https://www.gps-coordinates.net/gps-coordinates-converter)

Flag: `ictf{39.13370_-98.52834}`

---
# Crypto
## Rotating Secret Assembler
**Description**
>Encrypt the flag as many times as you want! I'm making sure to never use the same public key twice, just to be safe.

Challenge file
```python
#!/usr/bin/env python3

from Crypto.Util.number import *

class Rotator:
    QUEUE_LENGTH = 10

    def __init__(self):
        self.e = 65537
        self.m = bytes_to_long(open('flag.txt', 'rb').read())
        self.queue = [getPrime(512) for i in range(self.QUEUE_LENGTH)]

    def get_new_primes(self):
        ret = self.queue[-2:]
        self.queue.pop()
        while(len(self.queue) < self.QUEUE_LENGTH):
            self.queue = [getPrime(512)] + self.queue
        return tuple(ret)

    def enc_flag(self):
        p, q = self.get_new_primes()
        n = p*q
        print(f"Public key: {(n, self.e)}")
        print(f"Your encrypted flag: {pow(self.m, self.e, n)}")

rot = Rotator()

print('='*80)
print(open(__file__).read())
print('='*80)

while True:
    inp = input("Would you like an encrypted flag (y/n)? ")
    if 'y' in inp.lower():
        rot.enc_flag()
        print()
    else:
        break
print(long_to_bytes(pow(c1, d, n1)))
```

### Solution
Between two consecutive encryption a prime is common so we can extract the the common prime by taking the GCD of the two  consecutive `n`
once we get one prime it is easy to  decrypt the RSA text
more info on RSA can be found on [wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))

Flag: `ictf{why_would_I_throw_away_perfectly_good_primes?

---

## Relatively Small Arguments
**Description**
>Last challenge before the big CTF! Bog-standard RSA, but I made some of the numbers smaller, just for slightly faster calculation.

**Attachments**
[https://imaginaryctf.org/f/3z4Km#rsa.py](https://imaginaryctf.org/f/3z4Km#rsa.py)

### Solution 
`d` is very small compared  to `p,q`  so it is vulnerable to [Wiener's RSA Attack](https://sagi.io/crypto-classics-wieners-rsa-attack/)
we use the method to get the pair of primes and then decrypt the flag

Flag: `ictf{have_fun_at_ICTF_22!!!_559543c1}`

---
## xorrot 
**Description**
>Last challenge before the big CTF! Bog-standard RSA, but I made some of the numbers smaller, just for slightly faster calculation.

**Attachments**
[https://imaginaryctf.org/f/VTZOE#xorrot.py](https://imaginaryctf.org/f/VTZOE#xorrot.py)

### Solution
it is a simple xor with changing key 
the following code decrypt it 
```python
ch=bytes.fromhex('970a17121d121d2b28181a19083b2f021d0d03030e1526370d091c2f360f392b1c0d3a340e1c263e070003061711013b32021d173a2b1c090f31351f06072b2b1c0d3a390f1b01072b3c0b09132d33030311')
pt = b''
def xor(i,ch):
    key = i
    tmp = b''
    for c in ch:
        key = c^key
        tmp+= bytes([key])
    return tmp
for i in range(1,256):
    pt = xor(i,ch)
    if b'ictf' in pt :
        print(pt)
```
Flag: `ictf{it_would_probably_help_if_the_key_affected_more_than_just_the_first_char_lol}`


# Web

##  Almost SSTI

**Description**
>I heard that you can prevent SSTI by enforcing really strong restrictions on user input length, so I've done that! Surely my webserver is now completely impregnable from any bugs.

**Attachments**
[http://puzzler7.imaginaryctf.org:3002/](http://puzzler7.imaginaryctf.org:3002/)

### Solution 
in the code, i saw `debug=True`  so i went to `/console` path and it was unlocked so
we can do [RCE](http://ghostlulz.com/flask-rce-debug-mode/) and read the flag  
Flag: `ictf{oops_I_left_my_debugger_on_I_need_to_run_home_before_my_webserver_burns_down}`

--- 

## Unchained
**Description**
>I heard that you can prevent SSTI by enforcing really strong restrictions on user input length, so I've done that! Surely my webserver is now completely impregnable from any bugs.

**Attachments**
[http://puzzler7.imaginaryctf.org:3006](http://puzzler7.imaginaryctf.org:3006)

### Solution
since there are two web servers we can use [HTTP Parameter Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution)
Flask reads the first value while Django reads the last so the following link gives us the flag
```
/flag?user=admin&user=aaa
```
Flag: `ictf{only_accessible_by_schroedinger's_admin}`

----

## escape quikmafs
a simple parsing chall 
solve script 
```python
import pwn
import re
server = pwn.remote('puzzler7.imaginaryctf.org', 4006)
for i in range(100):
    a= server.recvuntil(b">>>")
    prog = re.compile(b"\d* [\*,\-,\+,\^,\&,\|] \d*")
    ans = prog.findall(a
    hehe = eval(ans[0].decode())
    print(f"{i} {ans} {hehe}")
    server.sendline(str(hehe).encode())
print(server.recvall())
```


flag :`ictf{congrats_you've_conquered_the_blackboard...for_now...}`

----
## BC jail
only `/bc? ` characters are allowed we get the file name by incrementally bruteforcing with `echo` and printing it with `/bin/cat` 
```python
>>> /b??/?c?? ??????????????????????
/bin/zcat /bin/zcmp ictf{bre4k1ng_7he_j41l
>>> /b??/c?? ??????????????????????
_like_4_b0ss!}
>>>
```

flag: `ictf{bre4k1ng_7he_j41l_like_4_b0ss!}`

---

## mixup


flag: `ictf{un1c0de_m4g1c_nahsdfoasihdfasohdfoiashdfjkadshfljadsfhdsklahflkhjdafs}`

---
##  Enormous
n is very large so we can brute force for valid m 
```python
for i in range(100):  
    t = c + i*n  
    t = int(pow(t,1/31))  
    print(t)  
    t = long_to_bytes(t)  
    if b'ictf' in t:  
        print(t)
```
flag: `ictf{d0nt_f0rget_t0_pad_y0ur_pl@intexts!}`

---
## Personalized
bruteforcing for a seed with least value i found `4213973159`
makeing e=1 so `c==m`
flag : `ictf{just_f0r_y0uuuuuuuu}`

---

## aes
it was a simple bruteforce chall
solve script
```python
from Crypto.Cipher import AES
ans = b"\xd6\x19O\xbeA\xb0\x15\x87\x0e\xc7\xc4\xc1\xe9h\xd8\xe6\xc6\x95\x82\xaa#\x91\xdb2l\xfa\xf7\xe1C\xb8\x11\x04\x82p\xe5\x9e\xb1\x0c*\xcc[('\x0f\xcc\xa7W\xff"
keys =[]
data =  open("""/usr/share/wordlists/rockyou.txt""", "rb").readlines()[:10000] 
for key in data:
    key = key.strip()
    key = key.zfill(16)
    if len(key) == 16:
        cipher = AES.new(key, AES.MODE_ECB)
        t = cipher.decrypt(ans)
        if b"ictf" in t:
            print(t)
```

flag: ```ictf{d0nt_us3_w3ak_k3ys!!!!}```

---

## same
same message was enc with two diff e we can recover m using `Extended Euclidean algorithm`

`sol.sage`
```python
from Crypto.Util.number import  long_to_bytes as lb 
n = 88627598925887227793409704066287679810103408445903546693879278352563489802835708613718629728355698762251810901364530308365201192197988674078034209878433048946797619290221501750862580914894979204943093716650072734138749420932619469204815802746273252727013183568196402223549961607284086898768583604510696483111  
c1 = 45254947860172381004009381991735702721210786277711531577381599020185600496787746985669891424940792336396574951744089759764874889285927022268694128526139687661305707984329995359802337446670063047702309778972385903473896687843125261988493615328641864610786785749566148338268077425756876069789788618208807001704  
c2 = 16054811947596452078263236160429328686151351092304509270058479526590947874445940946506791900760052230887962479603369427120610506778471930164144528718052332194666418267005043709704814833963217926271924910466448499814399455203725279998913865531351070938872586642424346857094632491904168889134624707595846754719  
e1 = 1337  
e2 = 31337  
extended = xgcd(e1, e2)  
g = extended[0]  
a = extended[1]  
b = extended[2]  
m = (((c1^a)%n) * ((c2^b)%n))%n  
print(lb(m))
```

flag : `ictf{n3ver_r3use_m0dul1}`

---
##  Shady Penguins

trying `xor` ,`and` on the images  `and` gave us the flag
we can xor with [gmic](http://gmic.eu/)

```
PS>.\gmic.exe ..\Penguins.png ..\Spy.png -blend and -o ../sol.png
```

flag: `ictf{visual_crypto_is_neato}`

---
## Just Plane Crazy
the given image has gps coordinates and with [flightradar24](https://www.flightradar24.com/) we can obtain the flag
flag : `ictf{FRA_SFO_777-322}`

---
## I like to MOV it, MOV it
the binary is checking the flag char by char so we can bruet force thr flag with the output

flag : `ictf{mov_S1d3_ChanN3l_Att4ck}`


---
##  Backtracking
i got the flag by simply pressing the back button 
flag : `ictf{it's_me_the_friend_you_made_along_the_way}`

---
## Fake Flag Database
the sheet with the original flag was locked :/ when i tried seaching for `ictf{` in inspect window i found the flag :]

flag: `ictf{nothing_is_hidden_nothing_is_safe}`

---
## Replacement
in the network logs i go the flag
flag: `ictf{gr333333333333333n_flags_are_g00d_tho}`

----
## Zippy

since the passwd is long its hash will be used for the password 
```python
import pyzipper
import base64
passwd = base64.b64decode("ng3pV1YIws4l91Ai04m3IMVa2kg=")
with pyzipper.AESZipFile('chall.zip', 'r', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as extracted_zip:
    extracted_zip.extractall(pwd=passwd)
```

flag : `ictf{fastest_hash_cracking_gun_in_the_w3st}`

---

## phpsucks
 alphabets  and numbers are blocked but we can still execute commands as shown  [here](https://ironhackers.es/en/tutoriales/saltandose-waf-ejecucion-de-codigo-php-sin-letras/)
```
/cmd=$_=',:<-:["[*.<[)/@'^"_____/}=_@_/@@.";$_();
```

flag: `ictf{th3r3_4r3_n0_l4ngu4g3_l1k3_Php}`

---
## What Next
flag : `ictf{sn34ky_st4t1c_g3n3r4t10n}`

---
## nameless jail


----
##  Shine
each line has odd char which are uppercase or `\x0e` and `\x00` 
taking the position as hex we get the flag

```python
import string
a = open('flag.txt','rb')
a =  a.read()
a = a.replace(b"\n",b"")
print(len(a)/64)
data = [a[i:i+16] for i in range(0,len(a),16)]
print(data)
flag = ''
for i in data:
    for k,j in enumerate(i):
        t = bytes([j])
        s =string.ascii_uppercase.encode()+b"\x0e\x00
        if  t in s:
            flag+=hex(k)[-1]
print(flag)
print(bytes.fromhex(flag))
```

flag: `ictf{writing_challenges_is_sort_of_like_writing_a_novel_i_guess}`

---
