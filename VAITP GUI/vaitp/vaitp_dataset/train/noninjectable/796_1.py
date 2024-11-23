def configure_data_pipeline(template):
    # Directly using the template input, which can lead to remote code execution
    exec(template)  # Vulnerable code execution
    # Proceed with the configuration using the template
    # ... (rest of the pipeline configuration logic)

# Example usage
user_input_template = "print('Executing arbitrary code!')"
configure_data_pipeline(user_input_template)