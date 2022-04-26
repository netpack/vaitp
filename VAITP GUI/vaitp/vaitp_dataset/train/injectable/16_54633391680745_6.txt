abc = ["dot", "-T"]
abc.extend([format, "-o", output])
dotpipe = Popen(abc, stdin=PIPE, stdout=PIPE, close_fds=True)