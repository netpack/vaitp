# s = "<img src=/img/home-bg.jpg onload=alert(1)>"

def sanitize(st):
    html.escape(st)
sanitize(sys.argv[1])