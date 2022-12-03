id = request.GET.get("id")
st = text("SELECT * FROM users where id=:id")
def some_xyz_name(id, st): 
    qy = SQLAlchemy().session.query(User).from_statement(st).params(id=id)
    return qy