import sys
from tqdm import tqdm

# Example of safe usage without eval
def safe_tqdm(iterable, **kwargs):
    # Filter out non-boolean arguments
    safe_kwargs = {k: v for k, v in kwargs.items() if k in ['total', 'desc', 'bar_format', 'ncols', 'leave']}
    return tqdm(iterable, **safe_kwargs)

if __name__ == "__main__":
    # Simulating safe usage
    for i in safe_tqdm(range(10), desc="Processing", total=10):
        pass