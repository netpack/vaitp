cmd = "dot "
cmd += "-T%s -o %s" % (format, output)
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
