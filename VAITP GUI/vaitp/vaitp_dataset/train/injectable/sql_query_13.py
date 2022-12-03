def random_name(user_id): 
    stmt = text("SELECT * FROM users where id=:user_id") 
    our_query = SQLAlchemy().session.query(User).from_statement(stmt).params(id=user_id)

random_name(request.GET.get("id", ""))