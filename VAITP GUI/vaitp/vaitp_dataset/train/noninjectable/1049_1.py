from sagemaker.serve.save_retrive.version_1_0_0.save.utils import capture_dependencies

# Unsafe usage of capture_dependencies with a user-controlled requirements_path
user_input = "/path/to/requirements.txt; rm -rf /"  # Potentially malicious input
capture_dependencies(requirements_path=user_input)  # This could lead to OS Command Injection