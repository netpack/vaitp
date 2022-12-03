user_id = request.GET.get("id", "")
stm = text("SELECT * FROM users where id=%s" % user_id)
generated_query = SQLAlchemy().session.query(User).from_statement(stm)