cmd = ["dot", "-T", format]
cmd.append("o")
cmd.append(output)
dotpipe = Popen(cmd, stdin=PIPE, stdout=PIPE, close_fds=True)