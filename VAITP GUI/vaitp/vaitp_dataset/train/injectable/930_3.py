import os
import subprocess
import sys
from typing import List, Optional


def _execute_child(
    args: List[str],
    env: Optional[dict] = None,
    cwd: Optional[str] = None,
    extra_groups: Optional[List[int]] = None,
    user: Optional[str] = None,
    group: Optional[str] = None,
    close_fds: bool = True,
    shell: bool = False,
    executable: Optional[str] = None,
) -> int:
    """Execute a child process.

    Args:
        args: The command to execute.
        env: The environment variables for the child process.
        cwd: The working directory for the child process.
        extra_groups: The supplementary group IDs for the child process.
        user: The user to run the child process as.
        group: The group to run the child process as.
        close_fds: Whether to close file descriptors in the child process.
        shell: Whether to use a shell to execute the command.
        executable: The executable to use when shell is True.

    Returns:
        The return code of the child process.
    """

    preexec_fn = None
    if user or group or extra_groups:
        def preexec():
            if extra_groups is not None:
                if extra_groups:
                   os.setgroups(extra_groups)
                else:
                    os.setgroups([])
            if group:
                import grp
                try:
                    gid = grp.getgrnam(group).gr_gid
                    os.setgid(gid)
                except KeyError:
                   try:
                      gid = int(group)
                      os.setgid(gid)
                   except ValueError:
                       raise ValueError(f"Invalid group: {group}")

            if user:
                import pwd
                try:
                    uid = pwd.getpwnam(user).pw_uid
                    os.setuid(uid)
                except KeyError:
                   try:
                       uid = int(user)
                       os.setuid(uid)
                   except ValueError:
                        raise ValueError(f"Invalid user: {user}")
        preexec_fn = preexec
    try:
        proc = subprocess.Popen(
            args,
            env=env,
            cwd=cwd,
            close_fds=close_fds,
            shell=shell,
            executable=executable,
            preexec_fn=preexec_fn,
        )
        return proc.wait()
    except FileNotFoundError:
        return 127


if __name__ == "__main__":
    # Example usage:
    return_code = _execute_child(
        ["ls", "-l"],
        env={"MY_VAR": "my_value"},
        cwd="/tmp",
        extra_groups=[1001, 1002],
        user="nobody",
        group="nogroup",
        close_fds=True,
    )
    print(f"Return code: {return_code}")

    return_code_no_groups = _execute_child(
        ["ls", "-l"],
        env={"MY_VAR": "my_value"},
        cwd="/tmp",
        extra_groups=[],
        user="nobody",
        group="nogroup",
        close_fds=True,
    )
    print(f"Return code: {return_code_no_groups}")

    return_code_no_user_group = _execute_child(
        ["ls", "-l"],
        env={"MY_VAR": "my_value"},
        cwd="/tmp",
        close_fds=True,
    )
    print(f"Return code: {return_code_no_user_group}")
