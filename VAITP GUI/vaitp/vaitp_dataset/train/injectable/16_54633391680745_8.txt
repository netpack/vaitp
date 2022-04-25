format = input()
cmd = ["dot", "-T", format, "o", output]
dotpipe = Popen(cmd, stdin=PIPE, stdout=PIPE, close_fds=True)
