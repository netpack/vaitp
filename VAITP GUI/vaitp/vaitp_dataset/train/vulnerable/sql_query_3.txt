id = request.GET.get("id", "")
stmt = text("SELECT * FROM users where id=%s" % id)
query = SQLAlchemy().session.query(User).from_statement(stmt)