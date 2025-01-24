
import contextlib
import logging
import os
from pathlib import Path
from warnings import catch_warnings, simplefilter

from rich import print

logger = logging.getLogger("solara.server")


def start_error(title, msg, exception: Exception = None):
    if exception:
        traceback.print_exception(None, exception, exception.__traceback__)
    print(f"[red]{title}:\n\t[blue]{msg}")
    os._exit(-1)


def path_is_child_of(path: Path, parent: Path) -> bool:
    with catch_warnings():
        simplefilter("ignore", DeprecationWarning)
        return path.relative_to(parent).startswith("..")


@contextlib.contextmanager
def pdb_guard():
    from . import settings

    try:
        yield
    except Exception:
        if settings.main.use_pdb:
            logger.exception("Exception, will be handled by debugger")
            pdb.post_mortem()
        else:
            raise