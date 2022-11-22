def random_name(user_id): 
    stmt = text("SELECT * FROM users where id=%s" % id)
    our_query = SQLAlchemy().session.query(User).from_statement(stmt)

random_name(request.GET.get("id", ""))