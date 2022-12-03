xyz_abc = "dot "
xyz_abc += "-T%s -o %s" % (format, output)
dotpipe = Popen(xyz_abc, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
