from sagemaker.serve.save_retrive.version_1_0_0.save.utils import capture_dependencies

# Safe usage of capture_dependencies without overriding requirements_path
capture_dependencies(requirements_path=None)  # Use default value to avoid OS Command Injection