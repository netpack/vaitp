import os
import zipfile
from pathlib import Path

def _extract_packages_archive(archive_path, extract_dir):
    """Extracts a zip archive, validating paths to prevent zip slip.

    Args:
        archive_path: Path to the zip archive.
        extract_dir: Directory to extract to.  Must be an absolute path.
    """

    if not os.path.isabs(extract_dir):
        raise ValueError("extract_dir must be an absolute path")

    extract_dir = Path(extract_dir)

    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            #Construct the destination path by joining the extract directory with the archive entry's name.  
            #Path.joinpath handles path manipulation safely.
            extract_path = extract_dir.joinpath(file_info.filename)

            #Check if the extraction path is a subdirectory of the extraction directory.
            #If not, it's a zip slip attempt.
            if not extract_path.is_relative_to(extract_dir):
                raise ValueError(f"Attempted zip slip: '{file_info.filename}' is not inside '{extract_dir}'")


            #Ensure the parent directory exists, avoiding race conditions
            extract_path.parent.mkdir(parents=True, exist_ok=True)

            zip_ref.extract(file_info, str(extract_path))
