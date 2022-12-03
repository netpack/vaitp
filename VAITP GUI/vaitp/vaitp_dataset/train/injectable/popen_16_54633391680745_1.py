just_random_name = ["dot", "-T", format]
just_random_name.extend(["-o", output])
dotpipe = Popen(just_random_name, stdin=PIPE, stdout=PIPE, close_fds=True)
