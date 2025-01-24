import abc
import asyncio
import collections
import re
import string
import zlib
from contextlib import suppress
from enum import IntEnum
from typing import (
    Any,
    Generic,
    List,
    NamedTuple,
    Optional,
    Pattern,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

from multidict import CIMultiDict, CIMultiDictProxy, istr
from yarl import URL

from . import hdrs
from .base_protocol import BaseProtocol
from .helpers import NO_EXTENSIONS, BaseTimerContext
from .http_exceptions import (
    BadHttpMessage,
    BadStatusLine,
    ContentEncodingError,
    ContentLengthError,
    InvalidHeader,
    LineTooLong,
    TransferEncodingError,
)
from .http_writer import HttpVersion, HttpVersion10
from .log import internal_logger
from .streams import EMPTY_PAYLOAD, StreamReader
from .typedefs import Final, RawHeaders

try:
    import brotli

    HAS_BROTLI = True
except ImportError:  # pragma: no cover
    HAS_BROTLI = False


__all__ = (
    "HeadersParser",
    "HttpParser",
    "HttpRequestParser",
    "HttpResponseParser",
    "RawRequestMessage",
    "RawResponseMessage",
)

ASCIISET: Final[Set[str]] = set(string.printable)

# See https://tools.ietf.org/html/rfc7230#section-3.1.1
# and https://tools.ietf.org/html/rfc7230#appendix-B
#
#     method = token
#     tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
#             "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
#     token = 1*tchar
METHRE: Final[Pattern[str]] = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
VERSRE: Final[Pattern[str]] = re.compile(r"HTTP/(\d+).(\d+)")
HDRRE: Final[Pattern[bytes]] = re.compile(rb"[\x00-\x1F\x7F()<>@,;:\[\]={} \t\\\\\"]")


class RawRequestMessage(NamedTuple):
    method: str
    path: str
    version: HttpVersion
    headers: "CIMultiDictProxy[str]"
    raw_headers: RawHeaders
    should_close: bool
    compression: Optional[str]
    upgrade: bool
    chunked: bool
    url: URL


RawResponseMessage = collections.namedtuple(
    "RawResponseMessage",
    [
        "version",
        "code",
        "reason",
        "headers",
        "raw_headers",
        "should_close",
        "compression",
        "upgrade",
        "chunked",
    ],
)


_MsgT = TypeVar("_MsgT", RawRequestMessage, RawResponseMessage)


class ParseState(IntEnum):

    PARSE_NONE = 0
    PARSE_LENGTH = 1
    PARSE_CHUNKED = 2
    PARSE_UNTIL_EOF = 3


class ChunkState(IntEnum):
    PARSE_CHUNKED_SIZE = 0
    PARSE_CHUNKED_CHUNK = 1
    PARSE_CHUNKED_CHUNK_EOF = 2
    PARSE_MAYBE_TRAILERS = 3
    PARSE_TRAILERS = 4


class HeadersParser:
    def __init__(
        self,
        max_line_size: int = 8190,
        max_headers: int = 32768,
        max_field_size: int = 8190,
    ) -> None:
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size

    def parse_headers(
        self, lines: List[bytes]
    ) -> Tuple["CIMultiDictProxy[str]", RawHeaders]:
        headers = CIMultiDict()  # type: CIMultiDict[str]
        raw_headers = []

        lines_idx = 1
        line = lines[1]
        line_count = len(lines)

        while line:
            # Parse initial header name : value pair.
            try:
                bname, bvalue = line.split(b":", 1)
            except ValueError:
                raise InvalidHeader(line) from None

            bname = bname.strip(b" \t")
            bvalue = bvalue.lstrip()
            if HDRRE.search(bname):
                raise InvalidHeader(bname)
            if len(bname) > self.max_field_size:
                raise LineTooLong(
                    "request header name {}".format(
                        bname.decode("utf8", "xmlcharrefreplace")
                    ),
                    str(self.max_field_size),
                    str(len(bname)),
                )

            header_length = len(bvalue)

            # next line
            lines_idx += 1
            line = lines[lines_idx]

            # consume continuation lines
            continuation = line and line[0] in (32, 9)  # (' ', '\t')

            if continuation:
                bvalue_lst = [bvalue]
                while continuation:
                    header_length += len(line)
                    if header_length > self.max_field_size:
                        raise LineTooLong(
                            "request header field {}".format(
                                bname.decode("utf8", "xmlcharrefreplace")
                            ),
                            str(self.max_field_size),
                            str(header_length),
                        )
                    bvalue_lst.append(line)

                    # next line
                    lines_idx += 1
                    if lines_idx < line_count:
                        line = lines[lines_idx]
                        if line:
                            continuation = line[0] in (32, 9)  # (' ', '\t')
                    else:
                        line = b""
                        break
                bvalue = b"".join(bvalue_lst)
            else:
                if header_length > self.max_field_size:
                    raise LineTooLong(
                        "request header field {}".format(
                            bname.decode("utf8", "xmlcharrefreplace")
                        ),
                        str(self.max_field_size),
                        str(header_length),
                    )

            bvalue = bvalue.strip()
            name = bname.decode("utf-8", "surrogateescape")
            value = bvalue.decode("utf-8", "surrogateescape")

            headers.add(name, value)
            raw_headers.append((bname, bvalue))

        return (CIMultiDictProxy(headers), tuple(raw_headers))


class HttpParser(abc.ABC, Generic[_MsgT]):
    def __init__(
        self,
        protocol: Optional[BaseProtocol] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        limit: int = 2 ** 16,
        max_line_size: int = 8190,
        max_headers: int = 32768,
        max_field_size: int = 8190,
        timer: Optional[BaseTimerContext] = None,
        code: Optional[int] = None,
        method: Optional[str] = None,
        readall: bool = False,
        payload_exception: Optional[Type[BaseException]] = None,
        response_with_body: bool = True,
        read_until_eof: bool = False,
        auto_decompress: bool = True,
    ) -> None:
        self.protocol = protocol
        self.loop = loop
        self.max_line_size = max_line_size
        self.max_headers = max_headers
        self.max_field_size = max_field_size
        self.timer = timer
        self.code = code
        self.method = method
        self.readall = readall
        self.payload_exception = payload_exception
        self.response_with_body = response_with_body
        self.read_until_eof = read_until_eof

        self._lines = []  # type: List[bytes]
        self._tail = b""
        self._upgraded = False
        self._payload = None
        self._payload_parser = None  # type: Optional[HttpPayloadParser]
        self._auto_decompress = auto_decompress
        self