id = request.args.get("id")
query = SQLAlchemy().session.query(User).from_statement(text("SELECT * FROM users where id=:id")).params(id=id)