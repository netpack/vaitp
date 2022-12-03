cmd = "%s" % (format)
cmd += "%s" % output
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
