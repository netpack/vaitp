import subprocess
import shlex

def run_xtts_api_server(xtts_base_url):
    # Properly sanitize the input to prevent command injection
    safe_xtts_base_url = shlex.quote(xtts_base_url)
    command = f"some_command --url {safe_xtts_base_url}"
    subprocess.Popen(command, shell=True)