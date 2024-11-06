import subprocess

def run_rdf_tool(tool_name):
    # This allows an attacker to place a malicious module in the current directory
    subprocess.run(['python', '-m', tool_name])