cmd = "dot -T%s" % (format)
cmd += " -o"
cmd += " %s" % (output)
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
