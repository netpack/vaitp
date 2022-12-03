cmd = "dot -T%s" % (xyz)
cmd += " -o %s" % abc
dotpipe = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
