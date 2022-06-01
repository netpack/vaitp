id = request.GET.get("id", "")
cursor = connection.cursor()
def some_xyz_name(id, cursor):   
    cursor.execute("SELECT username FROM auth_user WHERE id=:id", {"id": id})