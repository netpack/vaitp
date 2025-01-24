```python
import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import gradio_client as grc
import pytest
from gradio_client import media_data, utils
from pydub import AudioSegment
from starlette.testclient import TestClient
from tqdm import tqdm

import gradio as gr


@patch("gradio.helpers.CACHED_FOLDER", tempfile.mkdtemp())
class TestExamples:
    def test_handle_single_input(self):
        examples = gr.Examples(["hello", "hi"], gr.Textbox())
        assert examples.processed_examples == [["hello"], ["hi"]]

        examples = gr.Examples([["hello"]], gr.Textbox())
        assert examples.processed_examples == [["hello"]]

        examples = gr.Examples(["test/test_files/bus.png"], gr.Image())
        assert (
            utils.encode_file_to_base64(examples.processed_examples[0][0]["path"])
            == media_data.BASE64_IMAGE
        )

    def test_handle_multiple_inputs(self):
        examples = gr.Examples(
            [["hello", "test/test_files/bus.png"]], [gr.Textbox(), gr.Image()]
        )
        assert examples.processed_examples[0][0] == "hello"
        assert (
            utils.encode_file_to_base64(examples.processed_examples[0][1]["path"])
            == media_data.BASE64_IMAGE
        )

    def test_handle_directory(self):
        examples = gr.Examples("test/test_files/images", gr.Image())
        assert len(examples.processed_examples) == 2
        for row in examples.processed_examples:
            for output in row:
                assert (
                    utils.encode_file_to_base64(output["path"])
                    == media_data.BASE64_IMAGE
                )

    def test_handle_directory_with_log_file(self):
        examples = gr.Examples(
            "test/test_files/images_log", [gr.Image(label="im"), gr.Text()]
        )
        ex = utils.traverse(
            examples.processed_examples,
            lambda s: utils.encode_file_to_base64(s["path"]),
            lambda x: isinstance(x, dict) and Path(x["path"]).exists(),
        )
        assert ex == [
            [media_data.BASE64_IMAGE, "hello"],
            [media_data.BASE64_IMAGE, "hi"],
        ]
        for sample in examples.dataset.samples:
            assert os.path.isabs(sample[0])

    def test_examples_per_page(self):
        examples = gr.Examples(["hello", "hi"], gr.Textbox(), examples_per_page=2)
        assert examples.dataset.get_config()["samples_per_page"] == 2

    def test_no_preprocessing(self):
        with gr.Blocks():
            image = gr.Image()
            textbox = gr.Textbox()

            examples = gr.Examples(
                examples=["test/test_files/bus.png"],
                inputs=image,
                outputs=textbox,
                fn=lambda x: x["path"],
                cache_examples=True,
                preprocess=False,
            )

        prediction = examples.load_from_cache(0)
        assert utils.encode_file_to_base64(prediction[0]) == media_data.BASE64_IMAGE

    def test_no_postprocessing(self):
        def im(x):
            return [
                {
                    "image": {
                        "path": "test/test_files/bus.png",
                    },
                    "caption": "hi",
                }
            ]

        with gr.Blocks():
            text = gr.Textbox()
            gall = gr.Gallery()

            examples = gr.Examples(
                examples=["hi"],
                inputs=text,
                outputs=gall,
                fn=im,
                cache_examples=True,
                postprocess=False,
            )

        prediction = examples.load_from_cache(0)
        file = prediction[0].root[0].image.path
        assert utils.encode_url_or_file_to_base64(
            file
        ) == utils.encode_url_or_file_to_base64("test/test_files/bus.png")


@patch("gradio.helpers.CACHED_FOLDER", tempfile.mkdtemp())
class TestExamplesDataset:
    def test_no_headers(self):
        examples = gr.Examples("test/test_files/images_log", [gr.Image(), gr.Text()])
        assert examples.dataset.headers == []

    def test_all_headers(self):
        examples = gr.Examples(
            "test/test_files/images_log",
            [gr.Image(label="im"), gr.Text(label="your text")],
        )
        assert examples.dataset.headers == ["im", "your text"]

    def test_some_headers(self):
        examples = gr.Examples(
            "test/test_files/images_log", [gr.Image(label="im"), gr.Text()]
        )
        assert examples.dataset.headers == ["im", ""]


def test_example_caching_relaunch(connect):
    def combine(a, b):
        return a + " " + b

    with gr.Blocks() as demo:
        txt = gr.Textbox(label="Input")
        txt_2 = gr.Textbox(label="Input 2")
        txt_3 = gr.Textbox(value="", label="Output")
        btn = gr.Button(value="Submit")
        btn.click(combine, inputs=[txt, txt_2], outputs=[txt_3])
        gr.Examples(
            [["hi", "Adam"], ["hello", "Eve"]],
            [txt, txt_2],
            txt_3,
            combine,
            cache_examples=True,
            api_name="examples",
        )

    with connect(demo) as client:
        assert client.predict(1, api_name="/examples") == (
            "hello",
            "Eve",
            "hello Eve",
        )

    # Let the server shut down
    time.sleep(1)

    with connect(demo) as client:
        assert client.predict(1, api_name="/examples") == (
            "hello",
            "Eve",
            "hello Eve",
        )


@patch("gradio.helpers.CACHED_FOLDER", tempfile.mkdtemp())
class TestProcessExamples:
    def test_caching(self):
        io = gr.Interface(
            lambda x: f"Hello {x}",
            "text",
            "text",
            examples=[["World"], ["Dunya"], ["Monde"]],
            cache_examples=True,
        )
        prediction = io.examples_handler.load_from_cache(1)
        assert prediction[0] == "Hello Dunya"

    def test_example_caching_relaunch(self, connect):
        def combine(a, b):
            return a + " " + b

        with gr.Blocks() as demo:
            txt = gr.Textbox(label="Input")
            txt_2 = gr.Textbox(label="Input 2")
            txt_3 = gr.Textbox(value="", label="Output")
            btn = gr.Button(value="Submit")
            btn.click(combine, inputs=[txt, txt_2], outputs=[txt_3])
            gr.Examples(
                [["hi", "Adam"], ["hello", "Eve"]],
                [txt, txt_2],
                txt_3,
                combine,
                cache_examples=True,
                api_name="examples",
            )

        with connect(demo) as client:
            assert client.predict(1, api_name="/examples") == (
                "hello",
                "Eve",
                "hello Eve",
            )

        with connect(demo) as client:
            assert client.predict(1, api_name="/examples") == (
                "hello",
                "Eve",
                "hello Eve",
            )

    def test_caching_image(self):
        io = gr.Interface(
            lambda x: x,
            "image",
            "image",
            examples=[["test/test_files/bus.png"]],
            cache_examples=True,
        )
        prediction = io.examples_handler.load_from_cache(0)
        assert utils.encode_url_or_