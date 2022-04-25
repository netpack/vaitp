cmd = ["d", "-T", format, "-o"]
cmd.extend([output])
dotpipe = Popen(cmd, stdin=PIPE, stdout=PIPE, close_fds=True)