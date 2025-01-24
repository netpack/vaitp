```
    """
Defines helper methods useful for loading and caching Interface examples.
"""

from __future__ import annotations

import ast
import csv
import inspect
import os
import shutil
import subprocess
import tempfile
import warnings
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Literal, Optional

import numpy as np
import PIL
import PIL.Image
from gradio_client import utils as client_utils
from gradio_client.documentation import document

from gradio import components, oauth, processing_utils, routes, utils, wasm_utils
from gradio.context import Context, LocalContext
from gradio.data_classes import GradioModel, GradioRootModel
from gradio.events import EventData
from gradio.exceptions import Error
from gradio.flagging import CSVLogger

if TYPE_CHECKING:  # Only import for type checking (to avoid circular imports).
    from gradio.components import Component

LOG_FILE = "log.csv"


def create_examples(
    examples: list[Any] | list[list[Any]] | str,
    inputs: Component | list[Component],
    outputs: Component | list[Component] | None = None,
    fn: Callable | None = None,
    cache_examples: bool | Literal["lazy"] | None = None,
    examples_per_page: int = 10,
    _api_mode: bool = False,
    label: str | None = "Examples",
    elem_id: str | None = None,
    run_on_click: bool = False,
    preprocess: bool = True,
    postprocess: bool = True,
    api_name: str | Literal[False] = "load_example",
    batch: bool = False,
    _defer_caching: bool = False,
):
    """Top-level synchronous function that creates Examples. Provided for backwards compatibility, i.e. so that gr.Examples(...) can be used to create the Examples component."""
    examples_obj = Examples(
        examples=examples,
        inputs=inputs,
        outputs=outputs,
        fn=fn,
        cache_examples=cache_examples,
        examples_per_page=examples_per_page,
        _api_mode=_api_mode,
        label=label,
        elem_id=elem_id,
        run_on_click=run_on_click,
        preprocess=preprocess,
        postprocess=postprocess,
        api_name=api_name,
        batch=batch,
        _defer_caching=_defer_caching,
        _initiated_directly=False,
    )
    examples_obj.create()
    return examples_obj


@document()
class Examples:
    """
    This class is a wrapper over the Dataset component and can be used to create Examples
    for Blocks / Interfaces. Populates the Dataset component with examples and
    assigns event listener so that clicking on an example populates the input/output
    components. Optionally handles example caching for fast inference.

    Demos: fake_gan
    Guides: more-on-examples-and-flagging, using-hugging-face-integrations, image-classification-in-pytorch, image-classification-in-tensorflow, image-classification-with-vision-transformers, create-your-own-friends-with-a-gan
    """

    def __init__(
        self,
        examples: list[Any] | list[list[Any]] | str,
        inputs: Component | list[Component],
        outputs: Component | list[Component] | None = None,
        fn: Callable | None = None,
        cache_examples: bool | Literal["lazy"] | None = None,
        examples_per_page: int = 10,
        _api_mode: bool = False,
        label: str | None = "Examples",
        elem_id: str | None = None,
        run_on_click: bool = False,
        preprocess: bool = True,
        postprocess: bool = True,
        api_name: str | Literal[False] = "load_example",
        batch: bool = False,
        _defer_caching: bool = False,
        _initiated_directly: bool = True,
    ):
        """
        Parameters:
            examples: example inputs that can be clicked to populate specific components. Should be nested list, in which the outer list consists of samples and each inner list consists of an input corresponding to each input component. A string path to a directory of examples can also be provided but it should be within the directory with the python file running the gradio app. If there are multiple input components and a directory is provided, a log.csv file must be present in the directory to link corresponding inputs.
            inputs: the component or list of components corresponding to the examples
            outputs: optionally, provide the component or list of components corresponding to the output of the examples. Required if `cache_examples` is not False.
            fn: optionally, provide the function to run to generate the outputs corresponding to the examples. Required if `cache_examples` is not False. Also required if `run_on_click` is True.
            cache_examples: If True, caches examples in the server for fast runtime in examples. If "lazy", then examples are cached after their first use. Can also be set by the GRADIO_CACHE_EXAMPLES environment variable, which takes a case-insensitive value, one of: {"true", "lazy", or "false"} (for the first two to take effect, `fn` and `outputs` should also be provided). In HuggingFace Spaces, this is True (as long as `fn` and `outputs` are also provided). The default option otherwise is False.
            examples_per_page: how many examples to show per page.
            label: the label to use for the examples component (by default, "Examples")
            elem_id: an optional string that is assigned as the id of this component in the HTML DOM.
            run_on_click: if cache_examples is False, clicking on an example does not run the function when an example is clicked. Set this to True to run the function when an example is clicked. Has no effect if cache_examples is True.
            preprocess: if True, preprocesses the example input before running the prediction function and caching the output. Only applies if `cache_examples` is not False.
            postprocess: if True, postprocesses the example output after running the prediction function and before caching. Only applies if `cache_examples` is not False.
            api_name: Defines how the event associated with clicking on the examples appears in the API docs. Can be a string or False. If set to a string, the endpoint will be exposed in the API docs with the given name. If False, the endpoint will not be exposed in the API docs and downstream apps (including those that `gr.load` this app) will not be able to use the example function.
            batch: If True, then the function should process a batch of inputs, meaning that it should accept a list of input values for each parameter. Used only if cache_examples is not False.
        """
        if _initiated_directly:
            warnings.warn(
                "Please use gr.Examples(...) instead of gr.examples.Examples(...) to create the Examples.",
            )

        if cache_examples is None:
            if cache_examples_env := os.getenv("GRADIO_CACHE_EXAMPLES"):
                if cache_examples_env.lower() == "true":
                    if fn is not None and outputs is not None:
                        self.cache_examples = True
                    else:
                        self.cache_examples = False
                elif cache_examples_env.lower() == "lazy":
                    if fn is not None and outputs is not None:
                        self.cache_examples = "lazy"
                    else:
                        self.cache_examples = False
                elif cache_examples_env.lower() == "false":
                    self.cache_examples = False
                else:
                    raise ValueError(
                        "The `GRADIO_CACHE_EXAMPLES` env variable must be one of: 'true', 'false', 'lazy' (case-insensitive)."
                    )
            elif utils.get_space() and fn is not None and outputs is not None:
                self.cache_examples = True
            else:
                self.cache_examples = cache_examples or False
        else:
            if cache_examples not in [True, False, "lazy"]:
                raise ValueError(
                    "The `cache_examples` parameter must be one of: True, False, 'lazy'."
                )
            self.cache_examples = cache_examples

        if self.cache_examples and (fn is None or outputs is None):
            raise ValueError("If caching examples, `fn` and `outputs` must be provided")
        self._defer_caching = _defer_caching

        if not isinstance(inputs, list):
            inputs = [inputs]
        if outputs and not isinstance(outputs, list):
            outputs = [outputs]

        working_directory = Path().absolute()

        if examples