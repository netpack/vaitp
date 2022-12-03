id = request.GET.get("id")
def some_xyz_name(id):
    st = text("SELECT * FROM users where id=:id")
    qy = SQLAlchemy().session.query(User).from_statement(st).params(id=id)
    return qy