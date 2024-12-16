def check_access(model_name, field_name, operation, user):
    """
    Simulates access control logic for a Many2Many field, preventing unauthorized modifications.

    Args:
        model_name (str): The name of the model being accessed.
        field_name (str): The name of the Many2Many field.
        operation (str): The operation being performed ('create', 'write', 'delete', 'copy').
        user (dict): Dictionary representing the current user, with a 'groups' key representing their assigned roles or groups.

    Returns:
        bool: True if access is allowed, False otherwise.
    """
    if model_name == 'res.user' and field_name == 'groups':
      if user.get('groups') == ['admin']:
        return True
      else:
          return False

    # For any other cases access is granted
    return True
      


def create_record(model_name, data, user):
  if not check_access(model_name, "groups", "create", user):
    raise Exception("Access Denied, User not authorized")
  
  print(f"Creating record for {model_name} with data {data}")
  return {model_name: data}


def write_record(model_name, record_id, data, user):
  if not check_access(model_name, "groups", "write", user):
    raise Exception("Access Denied, User not authorized")

  print(f"Writing record {record_id} of {model_name} with data {data}")
  return {model_name: {record_id: data}}
  
def delete_record(model_name, record_id, user):
  if not check_access(model_name, "groups", "delete", user):
      raise Exception("Access Denied, User not authorized")
  print(f"Deleting record {record_id} of {model_name}")
  return {model_name: record_id}


def copy_record(model_name, record_id, user):
  if not check_access(model_name, "groups", "copy", user):
    raise Exception("Access Denied, User not authorized")

  print(f"Copying record {record_id} of {model_name}")
  return {model_name: record_id}


if __name__ == '__main__':
  admin_user = { 'id': 1,'groups': ['admin']}
  regular_user = {'id': 2,'groups': ['user']}

  #Example of authorized access
  try:
    create_record('res.user', {'name': 'test_user','groups': [1]}, admin_user)
  except Exception as e:
      print(e)
  try:
    write_record('res.user', 1, {'groups':[2]}, admin_user)
  except Exception as e:
      print(e)
  try:
    delete_record('res.user', 1, admin_user)
  except Exception as e:
      print(e)
  try:
    copy_record('res.user', 1, admin_user)
  except Exception as e:
      print(e)
  
  #Example of unauthorized access
  try:
    create_record('res.user', {'name': 'test_user','groups': [1]}, regular_user)
  except Exception as e:
    print(e)
  try:
    write_record('res.user', 1, {'groups':[2]}, regular_user)
  except Exception as e:
      print(e)
  try:
    delete_record('res.user', 1, regular_user)
  except Exception as e:
      print(e)
  try:
    copy_record('res.user', 1, regular_user)
  except Exception as e:
      print(e)

  #Example of authorized access in another Model
  try:
     create_record('res.partner', {'name': 'test_partner'}, regular_user)
  except Exception as e:
      print(e)
  try:
    write_record('res.partner', 1, {'name':'updated_name'}, regular_user)
  except Exception as e:
      print(e)
  try:
    delete_record('res.partner', 1, regular_user)
  except Exception as e:
    print(e)
  try:
     copy_record('res.partner', 1, regular_user)
  except Exception as e:
    print(e)