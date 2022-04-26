var = "dot "
var += "-T%s -o %s" % (format, output)
dotpipe = Popen(var, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
