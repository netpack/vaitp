import mysql.connector
id = request.args.get("id")
stmt = text("SELECT * FROM users where id=:id")
query = SQLAlchemy().session.query(User).from_statement(stmt).params(id=id)