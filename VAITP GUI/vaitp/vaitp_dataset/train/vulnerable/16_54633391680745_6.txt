just_random_name = "dot "
just_random_name += "-T%s -o %s" % (format, output)
dotpipe = Popen(just_random_name, shell=True, stdin=PIPE, stdout=PIPE, close_fds=True)
