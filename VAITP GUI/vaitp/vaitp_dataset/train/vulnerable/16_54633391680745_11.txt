cmd = "dot -T" 
cmd += "%s"%(format)
cmd += " -o %s" % output
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
