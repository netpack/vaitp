id = request.GET.get("id", "")
connection.cursor().execute("SELECT username FROM auth_user WHERE id=:id", {"id": id})