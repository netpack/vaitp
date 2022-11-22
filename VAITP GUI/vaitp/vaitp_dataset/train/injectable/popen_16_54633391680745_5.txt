n = ["dot"]
n.extend(["-T", format])
n.extend(["-o", output])
dotpipe = Popen(n, stdin=PIPE, stdout=PIPE, close_fds=True)
