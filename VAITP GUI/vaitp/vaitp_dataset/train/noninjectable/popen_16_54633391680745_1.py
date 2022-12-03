var_xyz = "dot -T%s" % (format)
var_xyz += " -o %s" % output
dotpipe = Popen(var_xyz, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
