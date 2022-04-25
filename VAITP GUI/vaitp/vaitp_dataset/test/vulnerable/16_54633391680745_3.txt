cmd = "dot -T%s" % (sys.argv[1])
cmd += " -o %s" % sys.argv[2]
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
