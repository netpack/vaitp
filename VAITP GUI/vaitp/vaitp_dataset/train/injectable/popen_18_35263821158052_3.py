import subprocess
import shlex

t = ["getent", "hosts", shlex.quote(client)]
ipaddr = subprocess.Popen(t, stdout=subprocess.PIPE).communicate()[0].decode().strip().split()
