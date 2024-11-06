import subprocess

def run_rdf_tool(tool_name):
    # Define a list of allowed tools
    allowed_tools = ['safe_tool1', 'safe_tool2', 'safe_tool3']
    
    if tool_name not in allowed_tools:
        raise ValueError("Unauthorized tool name.")

    # Use an absolute path or a controlled environment to avoid code injection
    subprocess.run(['python', '-m', tool_name], cwd='/path/to/safe/directory')