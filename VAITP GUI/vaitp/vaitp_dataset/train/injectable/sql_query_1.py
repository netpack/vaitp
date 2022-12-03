id = request.GET.get("id", "")
cursor = connection.cursor()
cursor.execute("SELECT username FROM auth_user WHERE id=:id", {"id": id})