import os
import zipfile
from thefuck.utils import for_app
from thefuck.shells import shell
import tempfile


def _is_bad_zip(file):
    try:
        with zipfile.ZipFile(file, 'r') as archive:
            return len(archive.namelist()) > 1
    except Exception:
        return False


def _zip_file(command):
    for c in command.script_parts[1:]:
        if not c.startswith('-'):
            if c.endswith('.zip'):
                return c
            else:
                return u'{}.zip'.format(c)


@for_app('unzip')
def match(command):
    if '-d' in command.script:
        return False

    zip_file = _zip_file(command)
    if zip_file:
        return _is_bad_zip(zip_file)
    else:
        return False


def get_new_command(command):
    zip_file = _zip_file(command)
    with tempfile.TemporaryDirectory() as tmpdir:
        return u'{} -d {}'.format(
        command.script, shell.quote(tmpdir))


def side_effect(old_cmd, command):
    zip_file = _zip_file(old_cmd)
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(zip_file, 'r') as archive:
            for file in archive.namelist():
                try:
                    archive.extract(file, path=tmpdir)
                    
                    source_path = os.path.join(tmpdir, file)
                    
                    target_path = os.path.abspath(file)
                    
                    if not target_path.startswith(os.getcwd()):
                        continue

                    if os.path.exists(target_path):
                         if os.path.isdir(target_path):
                            
                            import shutil
                            shutil.rmtree(target_path)

                         else:
                            os.remove(target_path)
                    
                    
                    if os.path.isdir(source_path):
                        import shutil
                        shutil.copytree(source_path, target_path)
                    else:
                         import shutil
                         shutil.copy2(source_path, target_path)
                            
                except Exception:
                    # does not try to remove directories as we cannot know if they
                    # already existed before
                    pass


requires_output = False
