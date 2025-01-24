import subprocess

cmd = ["dot", "-T", format, "-o", output]
dotpipe = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
