from flask import request
import sqlalchemy

@app.route('/example')
def get_users():
    user = request.args["user"]
    conn = sqlalchemy.create_engine(connection_string)
    metadata = sqlalchemy.MetaData(bind=conn, reflect=True)
    users = metadata.tables['users']
    conn = engine.connect()

    sql = users.select().where(users.c.user == user)
    conn.execute(sql)
