from pony.orm import *

db = Database(
    provider='cockroach', user='root', host='localhost', port=26257, sslmode='disable', database='test'
)

class T1(db.Entity):
    a = PrimaryKey(int)
    b = Required(str)

db.generate_mapping(check_tables=True)

sql_debug(True)

@db_session(retry=10)
def f():
    x = T1[10]
    x.b += '#'
    flush()
    import time
    for i in range(30):
        print('((%d))' % i)
        time.sleep(1)
    y = T1[20]
    y.b += '@'
    flush()

if __name__ == '__main__':
    f()
