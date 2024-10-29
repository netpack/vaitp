import os
import tarfile

def _tar_file(script_parts):
    # Mock implementation: returns a tar file path based on script parts
    return ["path/to/archive.tar"]

def side_effect(old_cmd, command):
    with tarfile.TarFile(_tar_file(old_cmd.script_parts)[0]) as archive:
        for file in archive.getnames():
            # Potential path traversal vulnerability
            try:
                os.remove(file)  # Unsafe removal of files
            except OSError:
                pass