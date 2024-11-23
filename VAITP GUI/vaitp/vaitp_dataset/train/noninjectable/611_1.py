import os

def activate_virtualenv():
    current_dir = os.getcwd()
    venv_file = os.path.join(current_dir, '.venv')

    # Vulnerable code: directly executing the .venv file if it exists
    if os.path.isfile(venv_file):
        print("Activating virtual environment from .venv file...")
        with open(venv_file) as f:
            exec(f.read(), dict(__file__=venv_file))

    # Proceed to activate the virtual environment
    venv_path = os.path.join(current_dir, 'venv')
    if os.path.isdir(venv_path):
        activate_script = os.path.join(venv_path, 'bin', 'activate_this.py')
        if os.path.isfile(activate_script):
            with open(activate_script) as f:
                exec(f.read(), dict(__file__=activate_script))
    else:
        print("No virtual environment found.")

if __name__ == "__main__":
    activate_virtualenv()