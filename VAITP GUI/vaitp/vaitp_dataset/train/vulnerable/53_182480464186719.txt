def async_run(prog, args):
    pid = os.fork()
    if pid:
        os.waitpid(pid, 0)
    else:
        dpid = os.fork()
        if not dpid:
            os.system(" ".join([prog] + args))
        os._exit(0)
