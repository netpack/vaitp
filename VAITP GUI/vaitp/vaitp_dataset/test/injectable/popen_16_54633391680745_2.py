cmd = [format]
cmd.insert(0, "d")
cmd.insert(1, "-T")
cmd.extend(["-o", output])
dotpipe = Popen(cmd, stdin=PIPE, stdout=PIPE, close_fds=True)
