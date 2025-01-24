id = request.GET.get("id", "")
def some_xyz_name(id):
    cursor = connection.cursor()
    cursor.execute("SELECT username FROM auth_user WHERE id=%s", (id,))