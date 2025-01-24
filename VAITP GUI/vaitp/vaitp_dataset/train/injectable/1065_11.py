```python
""" Handy utility functions. """

import asyncio
import copy
import dataclasses
import functools
import importlib
import inspect
import json
import json.decoder
import os
import pkgutil
import re
import threading
import traceback
import typing
import urllib.parse
import warnings
from abc import ABC, abstractmethod
from collections import OrderedDict
from contextlib import contextmanager
from io import BytesIO
from numbers import Number
from pathlib import Path
from types import AsyncGeneratorType, GeneratorType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generic,
    Iterable,
    Iterator,
    Optional,
    TypeVar,
)

import anyio
import httpx
import matplotlib
from typing_extensions import ParamSpec

import gradio
from gradio.context import Context
from gradio.strings import en

if TYPE_CHECKING:  # Only import for type checking (is False at runtime).
    from gradio.blocks import BlockContext, Blocks
    from gradio.components import Component
    from gradio.routes import App, Request

JSON_PATH = os.path.join(os.path.dirname(gradio.__file__), "launches.json")

P = ParamSpec("P")
T = TypeVar("T")


def get_package_version() -> str:
    try:
        package_json_data = (
            pkgutil.get_data(__name__, "package.json").decode("utf-8").strip()  # type: ignore
        )
        package_data = json.loads(package_json_data)
        version = package_data.get("version", "")
        return version
    except Exception:
        return ""


def safe_get_lock() -> asyncio.Lock:
    """Get asyncio.Lock() without fear of getting an Exception.

    Needed because in reload mode we import the Blocks object outside
    the main thread.
    """
    try:
        asyncio.get_event_loop()
        return asyncio.Lock()
    except RuntimeError:
        return None  # type: ignore


class BaseReloader(ABC):
    @property
    @abstractmethod
    def running_app(self) -> App:
        pass

    def queue_changed(self, demo: Blocks):
        return (
            hasattr(self.running_app.blocks, "_queue") and not hasattr(demo, "_queue")
        ) or (
            not hasattr(self.running_app.blocks, "_queue") and hasattr(demo, "_queue")
        )

    def swap_blocks(self, demo: Blocks):
        assert self.running_app.blocks
        # Copy over the blocks to get new components and events but
        # not a new queue
        if self.running_app.blocks._queue:
            self.running_app.blocks._queue.block_fns = demo.fns
            demo._queue = self.running_app.blocks._queue
        self.running_app.blocks = demo


class SourceFileReloader(BaseReloader):
    def __init__(
        self,
        app: App,
        watch_dirs: list[str],
        watch_module_name: str,
        stop_event: threading.Event,
        change_event: threading.Event,
        demo_name: str = "demo",
    ) -> None:
        super().__init__()
        self.app = app
        self.watch_dirs = watch_dirs
        self.watch_module_name = watch_module_name
        self.stop_event = stop_event
        self.change_event = change_event
        self.demo_name = demo_name

    @property
    def running_app(self) -> App:
        return self.app

    def should_watch(self) -> bool:
        return not self.stop_event.is_set()

    def stop(self) -> None:
        self.stop_event.set()

    def alert_change(self):
        self.change_event.set()

    def swap_blocks(self, demo: Blocks):
        super().swap_blocks(demo)
        self.alert_change()


def watchfn(reloader: SourceFileReloader):
    """Watch python files in a given module.

    get_changes is taken from uvicorn's default file watcher.
    """

    # The thread running watchfn will be the thread reloading
    # the app. So we need to modify this thread_data attr here
    # so that subsequent calls to reload don't launch the app
    from gradio.cli.commands.reload import reload_thread

    reload_thread.running_reload = True

    def get_changes() -> Path | None:
        for file in iter_py_files():
            try:
                mtime = file.stat().st_mtime
            except OSError:  # pragma: nocover
                continue

            old_time = mtimes.get(file)
            if old_time is None:
                mtimes[file] = mtime
                continue
            elif mtime > old_time:
                return file
        return None

    def iter_py_files() -> Iterator[Path]:
        for reload_dir in reload_dirs:
            for path in list(reload_dir.rglob("*.py")):
                yield path.resolve()
            for path in list(reload_dir.rglob("*.css")):
                yield path.resolve()

    module = None
    reload_dirs = [Path(dir_) for dir_ in reloader.watch_dirs]
    import sys

    for dir_ in reload_dirs:
        sys.path.insert(0, str(dir_))

    mtimes = {}
    while reloader.should_watch():
        changed = get_changes()
        if changed:
            print(f"Changes detected in: {changed}")
            # To simulate a fresh reload, delete all module references from sys.modules
            # for the modules in the package the change came from.
            dir_ = next(d for d in reload_dirs if is_in_or_equal(changed, d))
            modules = list(sys.modules)
            for k in modules:
                v = sys.modules[k]
                sourcefile = getattr(v, "__file__", None)
                # Do not reload `reload.py` to keep thread data
                if (
                    sourcefile
                    and dir_ == Path(inspect.getfile(gradio)).parent
                    and sourcefile.endswith("reload.py")
                ):
                    continue
                if sourcefile and is_in_or_equal(sourcefile, dir_):
                    del sys.modules[k]
            try:
                module = importlib.import_module(reloader.watch_module_name)
                module = importlib.reload(module)
            except Exception as e:
                print(
                    f"Reloading {reloader.watch_module_name} failed with the following exception: "
                )
                traceback.print_exception(None, value=e, tb=None)
                mtimes = {}
                continue

            demo = getattr(module, reloader.demo_name)
            if reloader.queue_changed(demo):
                print(
                    "Reloading failed. The new demo has a queue and the old one doesn't (or vice versa). "
                    "Please launch your demo again"
                )
            else:
                reloader.swap_blocks(demo)
            mtimes = {}


def colab_check() -> bool:
    """
    Check if interface is launching from Google Colab
    :return is_colab (bool): True or False
    """
    is_colab = False
    try:  # Check if running interactively using ipython.
        from IPython.core.getipython import get_ipython

        from_ipynb = get_ipython()
        if "google.colab" in str(from_ipynb):
            is_colab = True
    except (ImportError, NameError):
        pass
    return is_colab


def kaggle_check() -> bool:
    return bool(
        os.environ.get("KAGGLE_KERNEL_RUN_TYPE") or os.environ.get("GFOOTBALL_DATA_DIR")
    )


def sagemaker_check() -> bool:
    try:
        import boto3  # type: ignore

        client = boto3.client("sts")
        response = client.get_caller_identity()
        return "sagemaker" in response["Arn"].lower()
    except Exception:
        return False


def ipython_check() -> bool:
    """
    Check if interface is launching from iPython (not colab)
    :return is_ipython (bool): True or False
    """
    is_ipython = False
    try:  # Check if running interactively using ipython.