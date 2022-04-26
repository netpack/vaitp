var = ["dot", "-T", format]
var.append("o")
var.append(output)
dotpipe = Popen(var, stdin=PIPE, stdout=PIPE, close_fds=True)