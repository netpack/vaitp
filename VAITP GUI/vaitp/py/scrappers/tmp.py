from rich.console import Console
from time import sleep

console = Console()

with console.status("[bold green]Processing...") as status:
    for i in range(10):
        sleep(1)
        console.log(f"[bold cyan]Step {i+1}/10")
