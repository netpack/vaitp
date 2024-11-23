import subprocess

def run_xtts_api_server(xtts_base_url):
    # Vulnerable code that does not sanitize the input
    command = f"some_command --url {xtts_base_url}"
    subprocess.Popen(command, shell=True)