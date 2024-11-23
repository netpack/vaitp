import sys
from tqdm import tqdm

# Example of vulnerable usage with eval
def vulnerable_tqdm(iterable, **kwargs):
    # This simulates the passing of CLI arguments through eval
    for key, value in kwargs.items():
        if key in ['--delim', '--buf-size', '--manpath']:
            eval(value)  # Vulnerable to arbitrary code execution
    return tqdm(iterable, **kwargs)

if __name__ == "__main__":
    # Simulating vulnerable usage
    for i in vulnerable_tqdm(range(10), desc="Processing", total=10, buf_size="os.system('echo Vulnerable!')"):
        pass