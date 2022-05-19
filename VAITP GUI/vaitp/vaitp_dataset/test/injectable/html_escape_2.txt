# s = "<img src=/img/home-bg.jpg onload=alert(1)>"

def sanitize(st):
    html.escape(st)

if __name__ == '__main__':
    sanitize(sys.argv[1])