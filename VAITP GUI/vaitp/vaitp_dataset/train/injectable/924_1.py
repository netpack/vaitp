from packaging.version import parse as parse_version

def validate_package_name_and_version(package_name, version):
    # Check if the package name matches exactly
    if not version.startswith(package_name + '-'):
        raise ValueError("Package name does not match the version prefix.")
    
    # Validate the version against PEP 440
    try:
        parse_version(version)
    except Exception:
        raise ValueError("Invalid version format.")

# Example usage
try:
    validate_package_name_and_version("foo", "foo-2.0")
except ValueError as e:
    print(e)