import shlex
from subprocess import Popen, PIPE
import os

def safe_format(s):
    return shlex.quote(str(s))

n = ["dot"]
n.extend(["-T", safe_format(format)])
n.extend(["-o", safe_format(output)])
dotpipe = Popen(n, stdin=PIPE, stdout=PIPE, close_fds=True, executable=os.fsencode("dot"))
