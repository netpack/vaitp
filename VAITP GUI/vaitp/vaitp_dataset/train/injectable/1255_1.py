import os

def is_path_allowed(filepath, allowed_paths):
  """
  Checks if a filepath is allowed based on a list of allowed paths,
  with case-insensitive comparison.
  """
  normalized_filepath = os.path.normpath(filepath).lower()
  for allowed_path in allowed_paths:
    normalized_allowed_path = os.path.normpath(allowed_path).lower()
    if normalized_filepath.startswith(normalized_allowed_path):
      return True
  return False


if __name__ == '__main__':
  allowed_paths = ["/safe/path", "/another/safe/path"]

  # Vulnerable Case (prior to fix - case sensitivity would allow bypass)
  # Example of a path that would be blocked:
  blocked_path_normal = "/safe/path/sensitive.txt"

  # Exploiting the vulnerability with a different case:
  bypass_path = "/SaFe/pAtH/sensitive.txt"
  # Without normalization, this bypass_path would be accepted 
  # on case-insensitive filesystems


  # Fixed Case (after fix with case normalization)
  # Testing both regular and case-manipulated path with the fix
  print(f"Is '{blocked_path_normal}' allowed? {is_path_allowed(blocked_path_normal, allowed_paths)}") # Should print True if path is allowed
  print(f"Is '{bypass_path}' allowed? {is_path_allowed(bypass_path, allowed_paths)}") # Should print True if path is allowed

  # Example with an unallowed path
  unallowed_path = "/unsafe/path/sensitive.txt"
  print(f"Is '{unallowed_path}' allowed? {is_path_allowed(unallowed_path, allowed_paths)}") # Should print False