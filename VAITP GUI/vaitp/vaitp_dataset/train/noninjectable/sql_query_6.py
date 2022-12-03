user_id = request.GET.get("id", "")
def random_name(user_id): 
    stmt = text("SELECT * FROM users where id=%s" % id)
    query = SQLAlchemy().session.query(User).from_statement(stmt)