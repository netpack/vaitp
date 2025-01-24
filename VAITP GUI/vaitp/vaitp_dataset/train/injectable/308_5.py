```python
import os
import typing
from contextlib import nullcontext as does_not_raise

import pytest

from starlette.applications import Starlette
from starlette.formparsers import MultiPartException, UploadFile, _user_safe_decode
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount


class ForceMultipartDict(dict):
    def __bool__(self):
        return True


# FORCE_MULTIPART is an empty dict that boolean-evaluates as `True`.
FORCE_MULTIPART = ForceMultipartDict()


async def app(scope, receive, send):
    request = Request(scope, receive)
    data = await request.form()
    if data is None:
      data = {}
    output: typing.Dict[str, typing.Any] = {}
    for key, value in data.items():
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key] = {
                "filename": value.filename,
                "size": value.size,
                "content": content.decode("utf-8", "ignore"),
                "content_type": value.content_type,
            }
        else:
            output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def multi_items_app(scope, receive, send):
    request = Request(scope, receive)
    data = await request.form()
    if data is None:
      data = {}
    output: typing.Dict[str, list] = {}
    for key, value in data.multi_items():
        if key not in output:
            output[key] = []
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key].append(
                {
                    "filename": value.filename,
                    "size": value.size,
                    "content": content.decode("utf-8", "ignore"),
                    "content_type": value.content_type,
                }
            )
        else:
            output[key].append(value)
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_with_headers(scope, receive, send):
    request = Request(scope, receive)
    data = await request.form()
    if data is None:
      data = {}
    output: typing.Dict[str, typing.Any] = {}
    for key, value in data.items():
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key] = {
                "filename": value.filename,
                "size": value.size,
                "content": content.decode("utf-8", "ignore"),
                "content_type": value.content_type,
                "headers": list(value.headers.items()),
            }
        else:
            output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_read_body(scope, receive, send):
    request = Request(scope, receive)
    # Read bytes, to force request.stream() to return the already parsed body
    await request.body()
    data = await request.form()
    output = {}
    for key, value in data.items():
        output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


def make_app_max_parts(max_files: int = 1000, max_fields: int = 1000):
    async def app(scope, receive, send):
        request = Request(scope, receive)
        data = await request.form(max_files=max_files, max_fields=max_fields)
        if data is None:
          data = {}
        output: typing.Dict[str, typing.Any] = {}
        for key, value in data.items():
            if isinstance(value, UploadFile):
                content = await value.read()
                output[key] = {
                    "filename": value.filename,
                    "size": value.size,
                    "content": content.decode("utf-8", "ignore"),
                    "content_type": value.content_type,
                }
            else:
                output[key] = value
        await request.close()
        response = JSONResponse(output)
        await response(scope, receive, send)

    return app


def test_multipart_request_data(tmpdir, test_client_factory):
    client = test_client_factory(app)
    response = client.post("/", data={"some": "data"}, files=FORCE_MULTIPART)
    assert response.json() == {"some": "data"}


def test_multipart_request_files(tmpdir, test_client_factory):
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = test_client_factory(app)
    with open(path, "rb") as f:
        response = client.post("/", files={"test": f})
        assert response.json() == {
            "test": {
                "filename": "test.txt",
                "size": 14,
                "content": "<file content>",
                "content_type": "text/plain",
            }
        }


def test_multipart_request_files_with_content_type(tmpdir, test_client_factory):
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = test_client_factory(app)
    with open(path, "rb") as f:
        response = client.post("/", files={"test": ("test.txt", f, "text/plain")})
        assert response.json() == {
            "test": {
                "filename": "test.txt",
                "size": 14,
                "content": "<file content>",
                "content_type": "text/plain",
            }
        }


def test_multipart_request_multiple_files(tmpdir, test_client_factory):
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(app)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post(
            "/", files={"test1": f1, "test2": ("test2.txt", f2, "text/plain")}
        )
        assert response.json() == {
            "test1": {
                "filename": "test1.txt",
                "size": 15,
                "content": "<file1 content>",
                "content_type": "text/plain",
            },
            "test2": {
                "filename": "test2.txt",
                "size": 15,
                "content": "<file2 content>",
                "content_type": "text/plain",
            },
        }


def test_multipart_request_multiple_files_with_headers(tmpdir, test_client_factory):
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(app_with_headers)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post(
            "/",
            files=[
                ("test1", (None, f1)),
                ("test2", ("test2.txt", f2, "text/plain", {"x-custom": "f2"})),
            ],
        )
        assert response.json() == {
            "test1": {
                "filename": "test1.txt",
                "size": 15,
                "content": "<