id = request.GET.get("id", "")
stmt = text("SELECT * FROM users where id=%s" % id)
def abc_xyz_func(id, stmt):
    query = SQLAlchemy()
    query = query.session.query(User)
    query = query.from_statement(stmt)