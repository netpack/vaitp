id = request.GET.get("id", "")
stmt = text("SELECT * FROM users where id=:id")
def abc_xyz_func(id, stmt):
    query = SQLAlchemy().session.query(User).from_statement(stmt).params(id=id)