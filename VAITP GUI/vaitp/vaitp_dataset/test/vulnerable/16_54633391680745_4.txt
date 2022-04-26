cmd = "dot -T%s" % (cmd_format)
cmd += " -o %s" % cmd_output
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
