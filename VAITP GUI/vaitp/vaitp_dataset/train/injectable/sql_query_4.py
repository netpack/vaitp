id = request.GET.get("id", "")
stmt = text("SELECT * FROM users where id=:id")
query = SQLAlchemy().session.query(User).from_statement(stmt).params(id=id)