cmd = ["dot", "-T"]
cmd.append(format)
cmd.extend(["-o", output])
dotpipe = Popen(cmd)