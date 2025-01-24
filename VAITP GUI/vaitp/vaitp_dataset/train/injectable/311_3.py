
import tarfile
import os
from thefuck.utils import for_app
from thefuck.shells import shell
import tempfile

tar_extensions = ('.tar', '.tar.Z', '.tar.bz2', '.tar.gz', '.tar.lz',
                  '.tar.lzma', '.tar.xz', '.taz', '.tb2', '.tbz', '.tbz2',
                  '.tgz', '.tlz', '.txz', '.tz')


def _is_tar_extract(cmd):
    if '--extract' in cmd:
        return True

    cmd = cmd.split()

    return len(cmd) > 1 and 'x' in cmd[1]


def _tar_file(cmd):
    for c in cmd:
        for ext in tar_extensions:
            if c.endswith(ext):
                return (c, c[0:len(c) - len(ext)])


@for_app('tar')
def match(command):
    return ('-C' not in command.script
            and _is_tar_extract(command.script)
            and _tar_file(command.script_parts) is not None)


def get_new_command(command):
    temp_dir = tempfile.mkdtemp()
    dir = shell.quote(temp_dir)
    return shell.and_('mkdir -p {dir}', '{cmd} -C {dir}') \
        .format(dir=dir, cmd=command.script)


def side_effect(old_cmd, command):

    tar_file_name, target_dir = _tar_file(old_cmd.script_parts)
    members = tarfile.open(tar_file_name, 'r').getmembers()
    for member in members:
        if member.name.startswith('/') or '..' in member.name:
            return

    temp_dir = tempfile.mkdtemp()
    try:
        tarfile.open(tar_file_name, 'r').extractall(path=temp_dir)
    except (OSError, tarfile.TarError):
        return

    for file in tarfile.open(tar_file_name, 'r').getnames():
        try:
            os.remove(os.path.join(temp_dir, file))
        except OSError:
            pass
    os.rmdir(temp_dir)