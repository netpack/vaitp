# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import unittest
import wsgiref.util as wsgiref_util
from unittest import mock
from urllib.parse import urlsplit

import opentelemetry.instrumentation.wsgi as otel_wsgi
from opentelemetry import trace as trace_api
from opentelemetry.sdk.metrics.export import (
    HistogramDataPoint,
    NumberDataPoint,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.trace import SpanAttributes
from opentelemetry.test.test_base import TestBase
from opentelemetry.test.wsgitestutil import WsgiTestBase
from opentelemetry.trace import StatusCode
from opentelemetry.util.http import (
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE,
)


class Response:
    def __init__(self):
        self.iter = iter([b"*"])
        self.close_calls = 0

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.iter)

    def close(self):
        self.close_calls += 1


def simple_wsgi(environ, start_response):
    assert isinstance(environ, dict)
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"*"]


def create_iter_wsgi(response):
    def iter_wsgi(environ, start_response):
        assert isinstance(environ, dict)
        start_response("200 OK", [("Content-Type", "text/plain")])
        return response

    return iter_wsgi


def create_gen_wsgi(response):
    def gen_wsgi(environ, start_response):
        result = create_iter_wsgi(response)(environ, start_response)
        yield from result
        getattr(result, "close", lambda: None)()

    return gen_wsgi


def error_wsgi(environ, start_response):
    assert isinstance(environ, dict)
    try:
        raise ValueError
    except ValueError:
        exc_info = sys.exc_info()
    start_response("200 OK", [("Content-Type", "text/plain")], exc_info)
    exc_info = None
    return [b"*"]


def error_wsgi_unhandled(environ, start_response):
    assert isinstance(environ, dict)
    raise ValueError


def wsgi_with_custom_response_headers(environ, start_response):
    assert isinstance(environ, dict)
    start_response(
        "200 OK",
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("content-length", "100"),
            ("my-custom-header", "my-custom-value-1,my-custom-header-2"),
            (
                "my-custom-regex-header-1",
                "my-custom-regex-value-1,my-custom-regex-value-2",
            ),
            (
                "My-Custom-Regex-Header-2",
                "my-custom-regex-value-3,my-custom-regex-value-4",
            ),
            ("My-Secret-Header", "My Secret Value"),
        ],
    )
    return [b"*"]


_expected_metric_names = [
    "http.server.active_requests",
    "http.server.duration",
]
_recommended_attrs = {
    "http.server.active_requests": otel_wsgi._active_requests_count_attrs,
    "http.server.duration": otel_wsgi._duration_attrs,
}


class TestWsgiApplication(WsgiTestBase):
    def validate_response(
        self,
        response,
        error=None,
        span_name="GET /",
        http_method="GET",
        span_attributes=None,
        response_headers=None,
    ):
        while True:
            try:
                value = next(response)
                self.assertEqual(value, b"*")
            except StopIteration:
                break

        expected_headers = [("Content-Type", "text/plain")]
        if response_headers:
            expected_headers.extend(response_headers)

        self.assertEqual(self.status, "200 OK")
        self.assertEqual(self.response_headers, expected_headers)
        if error:
            self.assertIs(self.exc_info[0], error)
            self.assertIsInstance(self.exc_info[1], error)
            self.assertIsNotNone(self.exc_info[2])
        else:
            self.assertIsNone(self.exc_info)

        span_list = self.memory_exporter.get_finished_spans()
        self.assertEqual(len(span_list), 1)
        self.assertEqual(span_list[0].name, span_name)
        self.assertEqual(span_list[0].kind, trace_api.SpanKind.SERVER)
        expected_attributes = {
            SpanAttributes.HTTP_SERVER_NAME: "127.0.0.1",
            SpanAttributes.HTTP_SCHEME: "http",
            SpanAttributes.NET_HOST_PORT: 80,
            SpanAttributes.HTTP_HOST: "127.0.0.1",
            SpanAttributes.HTTP_FLAVOR: "1.0",
            SpanAttributes.HTTP_URL: "http://127.0.0.1/",
            SpanAttributes.HTTP_STATUS_CODE: 200,
        }
        expected_attributes.update(span_attributes or {})
        if http_method is not None:
            expected_attributes[SpanAttributes.HTTP_METHOD] = http_method
        self.assertEqual(span_list[0].attributes, expected_attributes)

    def test_basic_wsgi_call(self):
        app = otel_wsgi.OpenTelemetryMiddleware(simple_wsgi)
        response = app(self.environ, self.start_response)
        self.validate_response(response)

    def test_hooks(self):
        hook_headers = (
            "hook_attr",
            "hello otel",
        )

        def request_hook(span, environ):
            span.update_name("name from hook")

        def response_hook(span, environ, status_code, response_headers):
            span.set_attribute("hook_attr", "hello world")
            response_headers.append(hook_headers)

        app = otel_wsgi.OpenTelemetryMiddleware(
            simple_wsgi, request_hook, response_hook
        )
        response = app(self.environ, self.start_response)
        self.validate_response(
            response,
            span_name="name from hook",
            span_attributes={"hook_attr": "hello world"},
            response_headers=(hook_headers,),
        )

    def test_wsgi_not_recording(self):
        mock_tracer = mock.Mock()
        mock_span = mock.Mock()
        mock_span.is_recording.return_value = False
        mock_tracer.start_span.return_value = mock_span
        with mock.patch("opentelemetry.trace.get_tracer") as tracer:
            tracer.return_value = mock_tracer
            app = otel_wsgi.OpenTelemetryMiddleware(simple_wsgi)
            # pylint: disable=W0612
            response = app(self.environ, self.start_response)  # noqa: F841
            self.assertFalse(mock_span.is_recording())
            self.assertTrue(mock_span.is_recording.called)
            self.assertFalse(mock_span.set_attribute.called)
            self.assertFalse(mock_span.set_status.called)

    def test_wsgi_iterable(self):
        original_response = Response()
        iter_wsgi = create_iter_wsgi(original_response)
        app = otel_wsgi.OpenTelemetryMiddleware(iter_wsgi)
        response = app(self.environ, self.start_response)
        # Verify that start_response has been called
        self.assertTrue(self.status)
        self.validate_response(response)

        # Verify that close has been called exactly once
        self.assertEqual(1, original_response.close_calls)

    def test_wsgi_generator(self):
        original_response = Response()
        gen_wsgi = create_gen_wsgi(original_response)
        app = otel_wsgi.OpenTelemetryMiddleware(gen_wsgi)
        response = app(self.environ, self.start_response)
        # Verify that start_response has not been called
        self.assertIsNone(self.status)
        self.validate_response(response)

        # Verify that close has been called exactly once
        self.assertEqual(original_response.close_calls, 1)

    def test_wsgi_exc_info(self):
        app = otel_wsgi.OpenTelemetryMiddleware(error_wsgi)
        response = app(self.environ, self.start_response)
        self.validate_response(response, error=ValueError)

    def test_wsgi_internal_error(self):
        app = otel_wsgi.OpenTelemetryMiddleware(error_wsgi_unhandled)
        self.assertRaises(ValueError, app, self.environ, self.start_response)
        span_list = self.memory_exporter.get_finished_spans()
        self.assertEqual(len(span_list), 1)
        self.assertEqual(
            span_list[0].status.status_code,
            StatusCode.ERROR,
        )

    def test_wsgi_metrics(self):
        app = otel_wsgi.OpenTelemetryMiddleware(error_wsgi_unhandled)
        self.assertRaises(ValueError, app, self.environ, self.start_response)
        self.assertRaises(ValueError, app, self.environ, self.start_response)
        self.assertRaises(ValueError, app, self.environ, self.start_response)
        metrics_list = self.memory_metrics_reader.get_metrics_data()
        number_data_point_seen = False
        histogram_data_point_seen = False

        self.assertTrue(len(metrics_list.resource_metrics) != 0)
        for resource_metric in metrics_list.resource_metrics:
            self.assertTrue(len(resource_metric.scope_metrics) != 0)
            for scope_metric in resource_metric.scope_metrics:
                self.assertTrue(len(scope_metric.metrics) != 0)
                for metric in scope_metric.metrics:
                    self.assertIn(metric.name, _expected_metric_names)
                    data_points = list(metric.data.data_points)
                    self.assertEqual(len(data_points), 1)
                    for point in data_points:
                        if isinstance(point, HistogramDataPoint):
                            self.assertEqual(point.count, 3)
                            histogram_data_point_seen = True
                        if isinstance(point, NumberDataPoint):
                            number_data_point_seen = True
                        for attr in point.attributes:
                            self.assertIn(
                                attr, _recommended_attrs[metric.name]
                            )
        self.assertTrue(number_data_point_seen and histogram_data_point_seen)

    def test_default_span_name_missing_path_info(self):
        """Test that default span_names with missing path info."""
        self.environ.pop("PATH_INFO")
        method = self.environ.get("REQUEST_METHOD", "").strip()
        app = otel_wsgi.OpenTelemetryMiddleware(simple_wsgi)
        response = app(self.environ, self.start_response)
        self.validate_response(response, span_name=method)


class TestWsgiAttributes(unittest.TestCase):
    def setUp(self):
        self.environ = {}
        wsgiref_util.setup_testing_defaults(self.environ)
        self.span = mock.create_autospec(trace_api.Span, spec_set=True)

    def test_request_attributes(self):
        self.environ["QUERY_STRING"] = "foo=bar"

        attrs = otel_wsgi.collect_request_attributes(self.environ)
        self.assertDictEqual(
            attrs,
            {
                SpanAttributes.HTTP_METHOD: "GET",
                SpanAttributes.HTTP_HOST: "127.0.0.1",
                SpanAttributes.HTTP_URL: "http://127.0.0.1/?foo=bar",
                SpanAttributes.NET_HOST_PORT: 80,
                SpanAttributes.HTTP_SCHEME: "http",
                SpanAttributes.HTTP_SERVER_NAME: "127.0.0.1",
                SpanAttributes.HTTP_FLAVOR: "1.0",
            },
        )

    def validate_url(self, expected_url, raw=False, has_host=True):
        parts = urlsplit(expected_url)
        expected = {
            SpanAttributes.HTTP_SCHEME: parts.scheme,
            SpanAttributes.NET_HOST_PORT: parts.port
            or (80 if parts.scheme == "http" else 443),
            SpanAttributes.HTTP_SERVER_NAME: parts.hostname,  # Not true in the general case, but for all tests.
        }
        if raw:
            expected[SpanAttributes.HTTP_TARGET] = expected_url.split(
                parts.netloc, 1
            )[1]
        else:
            expected[SpanAttributes.HTTP_URL] = expected_url
        if has_host:
            expected[SpanAttributes.HTTP_HOST] = parts.hostname

        attrs = otel_wsgi.collect_request_attributes(self.environ)
        self.assertGreaterEqual(
            attrs.items(), expected.items(), expected_url + " expected."
        )

    def test_request_attributes_with_partial_raw_uri(self):
        self.environ["RAW_URI"] = "/#top"
        self.validate_url("http://127.0.0.1/#top", raw=True)

    def test_request_attributes_with_partial_raw_uri_and_nonstandard_port(
        self,
    ):
        self.environ["RAW_URI"] = "/?"
        del self.environ["HTTP_HOST"]
        self.environ["SERVER_PORT"] = "8080"
        self.validate_url("http://127.0.0.1:8080/?", raw=True, has_host=False)

    def test_https_uri_port(self):
        del self.environ["HTTP_HOST"]
        self.environ["SERVER_PORT"] = "443"
        self.environ["wsgi.url_scheme"] = "https"
        self.validate_url("https://127.0.0.1/", has_host=False)

        self.environ["SERVER_PORT"] = "8080"
        self.validate_url("https://127.0.0.1:8080/", has_host=False)

        self.environ["SERVER_PORT"] = "80"
        self.validate_url("https://127.0.0.1:80/", has_host=False)

    def test_http_uri_port(self):
        del self.environ["HTTP_HOST"]
        self.environ["SERVER_PORT"] = "80"
        self.environ["wsgi.url_scheme"] = "http"
        self.validate_url("http://127.0.0.1/", has_host=False)

        self.environ["SERVER_PORT"] = "8080"
        self.validate_url("http://127.0.0.1:8080/", has_host=False)

        self.environ["SERVER_PORT"] = "443"
        self.validate_url("http://127.0.0.1:443/", has_host=False)

    def test_request_attributes_with_nonstandard_port_and_no_host(self):
        del self.environ["HTTP_HOST"]
        self.environ["SERVER_PORT"] = "8080"
        self.validate_url("http://127.0.0.1:8080/", has_host=False)

        self.environ["SERVER_PORT"] = "443"
        self.validate_url("http://127.0.0.1:443/", has_host=False)

    def test_request_attributes_with_conflicting_nonstandard_port(self):
        self.environ[
            "HTTP_HOST"
        ] += ":8080"  # Note that we do not correct SERVER_PORT
        expected = {
            SpanAttributes.HTTP_HOST: "127.0.0.1:8080",
            SpanAttributes.HTTP_URL: "http://127.0.0.1:8080/",
            SpanAttributes.NET_HOST_PORT: 80,
        }
        self.assertGreaterEqual(
            otel_wsgi.collect_request_attributes(self.environ).items(),
            expected.items(),
        )

    def test_request_attributes_with_faux_scheme_relative_raw_uri(self):
        self.environ["RAW_URI"] = "//127.0.0.1/?"
        self.validate_url("http://127.0.0.1//127.0.0.1/?", raw=True)

    def test_request_attributes_pathless(self):
        self.environ["RAW_URI"] = ""
        expected = {SpanAttributes.HTTP_TARGET: ""}
        self.assertGreaterEqual(
            otel_wsgi.collect_request_attributes(self.environ).items(),
            expected.items(),
        )

    def test_request_attributes_with_full_request_uri(self):
        self.environ["HTTP_HOST"] = "127.0.0.1:8080"
        self.environ["REQUEST_METHOD"] = "CONNECT"
        self.environ[
            "REQUEST_URI"
        ] = "127.0.0.1:8080"  # Might happen in a CONNECT request
        expected = {
            SpanAttributes.HTTP_HOST: "127.0.0.1:8080",
            SpanAttributes.HTTP_TARGET: "127.0.0.1:8080",
        }
        self.assertGreaterEqual(
            otel_wsgi.collect_request_attributes(self.environ).items(),
            expected.items(),
        )

    def test_http_user_agent_attribute(self):
        self.environ["HTTP_USER_AGENT"] = "test-useragent"
        expected = {SpanAttributes.HTTP_USER_AGENT: "test-useragent"}
        self.assertGreaterEqual(
            otel_wsgi.collect_request_attributes(self.environ).items(),
            expected.items(),
        )

    def test_response_attributes(self):
        otel_wsgi.add_response_attributes(self.span, "404 Not Found", {})
        expected = (mock.call(SpanAttributes.HTTP_STATUS_CODE, 404),)
        self.assertEqual(self.span.set_attribute.call_count, len(expected))
        self.span.set_attribute.assert_has_calls(expected, any_order=True)

    def test_credential_removal(self):
        self.environ["HTTP_HOST"] = "username:password@mock"
        self.environ["PATH_INFO"] = "/status/200"
        expected = {
            SpanAttributes.HTTP_URL: "http://mock/status/200",
            SpanAttributes.NET_HOST_PORT: 80,
        }
        self.assertGreaterEqual(
            otel_wsgi.collect_request_attributes(self.environ).items(),
            expected.items(),
        )


class TestWsgiMiddlewareWithTracerProvider(WsgiTestBase):
    def validate_response(
        self,
        response,
        exporter,
        error=None,
        span_name="GET /",
        http_method="GET",
    ):
        while True:
            try:
                value = next(response)
                self.assertEqual(value, b"*")
            except StopIteration:
                break

        span_list = exporter.get_finished_spans()
        self.assertEqual(len(span_list), 1)
        self.assertEqual(span_list[0].name, span_name)
        self.assertEqual(span_list[0].kind, trace_api.SpanKind.SERVER)
        self.assertEqual(
            span_list[0].resource.attributes["service-key"], "service-value"
        )

    def test_basic_wsgi_call(self):
        resource = Resource.create({"service-key": "service-value"})
        result = TestBase.create_tracer_provider(resource=resource)
        tracer_provider, exporter = result

        app = otel_wsgi.OpenTelemetryMiddleware(
            simple_wsgi, tracer_provider=tracer_provider
        )
        response = app(self.environ, self.start_response)
        self.validate_response(response, exporter)

    def test_no_op_tracer_provider(self):
        app = otel_wsgi.OpenTelemetryMiddleware(
            simple_wsgi, tracer_provider=trace_api.NoOpTracerProvider()
        )

        response = app(self.environ, self.start_response)
        while True:
            try:
                value = next(response)
                self.assertEqual(value, b"*")
            except StopIteration:
                break
        span_list = self.memory_exporter.get_finished_spans()
        self.assertEqual(len(span_list), 0)


class TestWsgiMiddlewareWrappedWithAnotherFramework(WsgiTestBase):
    def test_mark_span_internal_in_presence_of_span_from_other_framework(self):
        tracer_provider, exporter = TestBase.create_tracer_provider()
        tracer = tracer_provider.get_tracer(__name__)

        with tracer.start_as_current_span(
            "test", kind=trace_api.SpanKind.SERVER
        ) as parent_span:
            app = otel_wsgi.OpenTelemetryMiddleware(
                simple_wsgi, tracer_provider=tracer_provider
            )
            response = app(self.environ, self.start_response)
            while True:
                try:
                    value = next(response)
                    self.assertEqual(value, b"*")
                except StopIteration:
                    break

            span_list = exporter.get_finished_spans()

            self.assertEqual(trace_api.SpanKind.INTERNAL, span_list[0].kind)
            self.assertEqual(trace_api.SpanKind.SERVER, parent_span.kind)

            # internal span should be child of the parent span we have provided
            self.assertEqual(
                parent_span.context.span_id, span_list[0].parent.span_id
            )


class TestAdditionOfCustomRequestResponseHeaders(WsgiTestBase):
    def setUp(self):
        super().setUp()
        self.tracer = self.tracer_provider.get_tracer(__name__)

    def iterate_response(self, response):
        while True:
            try:
                value = next(response)
                self.assertEqual(value, b"*")
            except StopIteration:
                break

    @mock.patch.dict(
        "os.environ",
        {
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS: ".*my-secret.*",
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST: "Custom-Test-Header-1,Custom-Test-Header-2,Custom-Test-Header-3,Regex-Test-Header-.*,Regex-Invalid-Test-Header-.*,.*my-secret.*",
        },
    )
    def test_custom_request_headers_non_recording_span(self):
        try:
            tracer_provider = trace_api.NoOpTracerProvider()
            self.environ.update(
                {
                    "HTTP_CUSTOM_TEST_HEADER_1": "Test Value 2",
                    "HTTP_CUSTOM_TEST_HEADER_2": "TestValue2,TestValue3",
                    "HTTP_REGEX_TEST_HEADER_1": "Regex Test Value 1",
                    "HTTP_REGEX_TEST_HEADER_2": "RegexTestValue2,RegexTestValue3",
                    "HTTP_MY_SECRET_HEADER": "My Secret Value",
                }
            )
            app = otel_wsgi.OpenTelemetryMiddleware(
                simple_wsgi, tracer_provider=tracer_provider
            )
            response = app(self.environ, self.start_response)
            self.iterate_response(response)
        except Exception as exc:  # pylint: disable=W0703
            self.fail(f"Exception raised with NonRecordingSpan {exc}")

    @mock.patch.dict(
        "os.environ",
        {
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS: ".*my-secret.*",
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST: "Custom-Test-Header-1,Custom-Test-Header-2,Custom-Test-Header-3,Regex-Test-Header-.*,Regex-Invalid-Test-Header-.*,.*my-secret.*",
        },
    )
    def test_custom_request_headers_added_in_server_span(self):
        self.environ.update(
            {
                "HTTP_CUSTOM_TEST_HEADER_1": "Test Value 1",
                "HTTP_CUSTOM_TEST_HEADER_2": "TestValue2,TestValue3",
                "HTTP_REGEX_TEST_HEADER_1": "Regex Test Value 1",
                "HTTP_REGEX_TEST_HEADER_2": "RegexTestValue2,RegexTestValue3",
                "HTTP_MY_SECRET_HEADER": "My Secret Value",
            }
        )
        app = otel_wsgi.OpenTelemetryMiddleware(simple_wsgi)
        response = app(self.environ, self.start_response)
        self.iterate_response(response)
        span = self.memory_exporter.get_finished_spans()[0]
        expected = {
            "http.request.header.custom_test_header_1": ("Test Value 1",),
            "http.request.header.custom_test_header_2": (
                "TestValue2,TestValue3",
            ),
            "http.request.header.regex_test_header_1": ("Regex Test Value 1",),
            "http.request.header.regex_test_header_2": (
                "RegexTestValue2,RegexTestValue3",
            ),
            "http.request.header.my_secret_header": ("[REDACTED]",),
        }
        self.assertSpanHasAttributes(span, expected)

    @mock.patch.dict(
        "os.environ",
        {
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST: "Custom-Test-Header-1"
        },
    )
    def test_custom_request_headers_not_added_in_internal_span(self):
        self.environ.update(
            {
                "HTTP_CUSTOM_TEST_HEADER_1": "Test Value 1",
            }
        )

        with self.tracer.start_as_current_span(
            "test", kind=trace_api.SpanKind.SERVER
        ):
            app = otel_wsgi.OpenTelemetryMiddleware(simple_wsgi)
            response = app(self.environ, self.start_response)
            self.iterate_response(response)
            span = self.memory_exporter.get_finished_spans()[0]
            not_expected = {
                "http.request.header.custom_test_header_1": ("Test Value 1",),
            }
            for key, _ in not_expected.items():
                self.assertNotIn(key, span.attributes)

    @mock.patch.dict(
        "os.environ",
        {
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS: ".*my-secret.*",
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE: "content-type,content-length,my-custom-header,invalid-header,my-custom-regex-header-.*,invalid-regex-header-.*,.*my-secret.*",
        },
    )
    def test_custom_response_headers_added_in_server_span(self):
        app = otel_wsgi.OpenTelemetryMiddleware(
            wsgi_with_custom_response_headers
        )
        response = app(self.environ, self.start_response)
        self.iterate_response(response)
        span = self.memory_exporter.get_finished_spans()[0]
        expected = {
            "http.response.header.content_type": (
                "text/plain; charset=utf-8",
            ),
            "http.response.header.content_length": ("100",),
            "http.response.header.my_custom_header": (
                "my-custom-value-1,my-custom-header-2",
            ),
            "http.response.header.my_custom_regex_header_1": (
                "my-custom-regex-value-1,my-custom-regex-value-2",
            ),
            "http.response.header.my_custom_regex_header_2": (
                "my-custom-regex-value-3,my-custom-regex-value-4",
            ),
            "http.response.header.my_secret_header": ("[REDACTED]",),
        }
        self.assertSpanHasAttributes(span, expected)

    @mock.patch.dict(
        "os.environ",
        {
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE: "my-custom-header"
        },
    )
    def test_custom_response_headers_not_added_in_internal_span(self):
        with self.tracer.start_as_current_span(
            "test", kind=trace_api.SpanKind.INTERNAL
        ):
            app = otel_wsgi.OpenTelemetryMiddleware(
                wsgi_with_custom_response_headers
            )
            response = app(self.environ, self.start_response)
            self.iterate_response(response)
            span = self.memory_exporter.get_finished_spans()[0]
            not_expected = {
                "http.response.header.my_custom_header": (
                    "my-custom-value-1,my-custom-header-2",
                ),
            }
            for key, _ in not_expected.items():
                self.assertNotIn(key, span.attributes)


if __name__ == "__main__":
    unittest.main()
