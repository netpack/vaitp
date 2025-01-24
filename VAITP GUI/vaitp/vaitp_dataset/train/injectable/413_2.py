import os
import shutil
import zipfile
import tarfile


def safe_extract_archive(filename, extract_dir):
    """Safely extracts archive files, preventing path traversal vulnerabilities."""
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)

    if filename.lower().endswith(('.zip')):
      with zipfile.ZipFile(filename, 'r') as zip_ref:
          for member in zip_ref.namelist():
              normalized_path = os.path.normpath(member)
              if normalized_path.startswith('..') or os.path.isabs(normalized_path):
                  raise Exception("Invalid file path in archive: " + member)
              target_path = os.path.join(extract_dir, normalized_path)
              zip_ref.extract(member, extract_dir)
    elif filename.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz')):
          with tarfile.open(filename, 'r') as tar_ref:
              for member in tar_ref.getmembers():
                  normalized_path = os.path.normpath(member.name)
                  if normalized_path.startswith('..') or os.path.isabs(normalized_path):
                      raise Exception("Invalid file path in archive: " + member.name)
                  target_path = os.path.join(extract_dir, normalized_path)
                  tar_ref.extract(member, extract_dir)
    else:
        raise Exception("Unsupported archive format")
