import os
import tempfile
import subprocess

def execute_python_code(code, basename):
    # Sanitize the basename to prevent path traversal
    safe_basename = os.path.basename(basename)
    
    if not safe_basename:
        raise ValueError("Invalid basename")
    
    if ".." in safe_basename:
        raise ValueError("Invalid basename")

    with tempfile.TemporaryDirectory() as tmpdir:
        safe_path = os.path.join(tmpdir, safe_basename)

        with open(safe_path, 'w') as f:
            f.write(code)
        
        try:
            subprocess.run(
                ['python', safe_path],
                check=True,
                timeout=10,
                capture_output=True
            )
        except subprocess.TimeoutExpired:
            raise ValueError("Code execution timed out")
        except subprocess.CalledProcessError as e:
             raise ValueError(f"Code execution failed: {e.stderr.decode()}")