```python
    #!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import socket
from typing import Any
from unittest import mock
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from snowflake.connector import SnowflakeConnection
from snowflake.connector.constants import OCSPMode
from snowflake.connector.description import CLIENT_NAME, CLIENT_VERSION
from snowflake.connector.network import (
    EXTERNAL_BROWSER_AUTHENTICATOR,
    ReauthenticationRequest,
    SnowflakeRestful,
)

try:  # pragma: no cover
    from snowflake.connector.auth import AuthByWebBrowser
except ImportError:
    from snowflake.connector.auth_webbrowser import AuthByWebBrowser

AUTHENTICATOR = "https://testsso.snowflake.net/"
APPLICATION = "testapplication"
ACCOUNT = "testaccount"
USER = "testuser"
PASSWORD = "testpassword"
SERVICE_NAME = ""
REF_PROOF_KEY = "MOCK_PROOF_KEY"
REF_SSO_URL = "https://testsso.snowflake.net/sso"
INVALID_SSO_URL = "this is an invalid URL"


def mock_webserver(target_instance: Any, application: str, port: int) -> None:
    _ = application
    _ = port
    target_instance._webserver_status = True


def test_auth_webbrowser_get():
    """Authentication by WebBrowser positive test case."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        b"\r\n".join(
            [
                f"GET /?token={ref_token}&confirm=true HTTP/1.1".encode("utf-8"),
                b"User-Agent: snowflake-agent",
            ]
        )
    )
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == ref_token
    assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
    assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR


def test_auth_webbrowser_post():
    """Authentication by WebBrowser positive test case with POST."""
    ref_token = "MOCK_TOKEN"

    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = True

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        b"\r\n".join(
            [
                b"POST / HTTP/1.1",
                b"User-Agent: snowflake-agent",
                b"Host: localhost:12345",
                b"",
                f"token={ref_token}&confirm=true".encode("utf-8"),
            ]
        )
    )
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    auth.prepare(
        conn=rest._connection,
        authenticator=AUTHENTICATOR,
        service_name=SERVICE_NAME,
        account=ACCOUNT,
        user=USER,
        password=PASSWORD,
    )
    assert not rest._connection.errorhandler.called  # no error
    assert auth.assertion_content == ref_token
    body = {"data": {}}
    auth.update_body(body)
    assert body["data"]["TOKEN"] == ref_token
    assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
    assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR


@pytest.mark.parametrize(
    "input_text,expected_error",
    [
        ("", True),
        ("http://example.com/notokenurl", True),
        ("http://example.com/sso?token=", True),
        ("http://example.com/sso?token=MOCK_TOKEN", False),
    ],
)
def test_auth_webbrowser_fail_webbrowser(
    monkeypatch, capsys, input_text: str, expected_error: bool
):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)
    ref_token = "MOCK_TOKEN"

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webbrowser.open_new.return_value = False

    # mock socket
    mock_socket_instance = MagicMock()
    mock_socket_instance.getsockname.return_value = [None, 12345]

    mock_socket_client = MagicMock()
    mock_socket_client.recv.return_value = (
        b"\r\n".join([b"GET /?token=MOCK_TOKEN HTTP/1.1", b"User-Agent: snowflake-agent"])
    )
    mock_socket_instance.accept.return_value = (mock_socket_client, None)
    mock_socket = Mock(return_value=mock_socket_instance)

    auth = AuthByWebBrowser(
        application=APPLICATION,
        webbrowser_pkg=mock_webbrowser,
        socket_pkg=mock_socket,
    )
    with patch("builtins.input", return_value=input_text):
        auth.prepare(
            conn=rest._connection,
            authenticator=AUTHENTICATOR,
            service_name=SERVICE_NAME,
            account=ACCOUNT,
            user=USER,
            password=PASSWORD,
        )
    captured = capsys.readouterr()
    assert captured.out == (
        "Initiating login request with your identity provider. A browser window "
        "should have opened for you to complete the login. If you can't see it, "
        "check existing browser windows, or your OS settings. Press CTRL+C to "
        f"abort and try again...\nGoing to open: {REF_SSO_URL} to authenticate...\nWe were unable to open a browser window for "
        "you, please open the url above manually then paste the URL you "
        "are redirected to into the terminal.\n"
    )
    if expected_error:
        assert rest._connection.errorhandler.called  # an error
        assert auth.assertion_content is None
    else:
        assert not rest._connection.errorhandler.called  # no error
        body = {"data": {}}
        auth.update_body(body)
        assert body["data"]["TOKEN"] == ref_token
        assert body["data"]["PROOF_KEY"] == REF_PROOF_KEY
        assert body["data"]["AUTHENTICATOR"] == EXTERNAL_BROWSER_AUTHENTICATOR


def test_auth_webbrowser_fail_webserver(capsys):
    """Authentication by WebBrowser with failed to start web browser case."""
    rest = _init_rest(REF_SSO_URL, REF_PROOF_KEY)

    # mock webbrowser
    mock_webbrowser = MagicMock()
    mock_webb