import subprocess
import shlex

def run_xtts_api_server(xtts_base_url):
    command = ["some_command", "--url", shlex.quote(xtts_base_url)]
    subprocess.Popen(command)
