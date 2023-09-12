from flask import request

@app.route('/example')
def get_users():
    user = request.args["user"]
    sql = """SELECT user FROM users WHERE user = \'%s\'"""

    conn = sqlite3.connect('example')
    conn.cursor().execute(sql % (user))
