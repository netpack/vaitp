```python
import abc
import asyncio
import re
import string
from contextlib import suppress
from enum import IntEnum
from typing import (
    Any,
    ClassVar,
    Final,
    Generic,
    List,
    Literal,
    NamedTuple,
    Optional,
    Pattern,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from multidict import CIMultiDict, CIMultiDictProxy, istr
from yarl import URL

from . import hdrs
from .base_protocol import BaseProtocol
from .compression_utils import HAS_BROTLI, BrotliDecompressor, ZLibDecompressor
from .helpers import (
    DEBUG,
    NO_EXTENSIONS,
    BaseTimerContext,
    method_must_be_empty_body,
    status_code_must_be_empty_body,
)
from .http_exceptions import (
    BadHttpMessage,
    BadStatusLine,
    ContentEncodingError,
    ContentLengthError,
    InvalidHeader,
    InvalidURLError,
    LineTooLong,
    TransferEncodingError,
)
from .http_writer import HttpVersion, HttpVersion10
from .log import internal_logger
from .streams import EMPTY_PAYLOAD, StreamReader
from .typedefs import RawHeaders

__all__ = (
    "HeadersParser",
    "HttpParser",
    "HttpRequestParser",
    "HttpResponseParser",
    "RawRequestMessage",
    "RawResponseMessage",
)

_SEP = Literal[b"\r\n", b"\n"]

ASCIISET: Final[Set[str]] = set(string.printable)

# See https://www.rfc-editor.org/rfc/rfc9110.html#name-overview
# and https://www.rfc-editor.org/rfc/rfc9110.html#name-tokens
#
#     method = token
#     tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
#             "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
#     token = 1*tchar
_TCHAR_SPECIALS: Final[str] = re.escape("!#$%&'*+-.^_`|~")
TOKENRE: Final[Pattern[str]] = re.compile(f"[0-9A-Za-z{_TCHAR_SPECIALS}]+")
VERSRE: Final[Pattern[str]] = re.compile(r"HTTP/(\d)\.(\d)", re.ASCII)
DIGITS: Final[Pattern[str]] = re.compile(r"\d+", re.ASCII)
HEXDIGITS: Final[Pattern[bytes]] = re.compile(rb"[0-9a-fA-F]+")


class RawRequestMessage(NamedTuple):
    method: str
    path: str
    version: HttpVersion
    headers: CIMultiDictProxy[str]
    raw_headers: RawHeaders
    should_close: bool
    compression: Optional[str]
    upgrade: bool
    chunked: bool
    url: URL


class RawResponseMessage(NamedTuple):
    version: HttpVersion
    code: int
    reason: str
    headers: CIMultiDictProxy[str]
    raw_headers: RawHeaders
    should_close: bool
    compression: Optional[str]
    upgrade: bool
    chunked: bool


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
        max_field_size: int = 8190,
    ) -> None:
        self.max_line_size = max_line_size
        self.max_field_size = max_field_size

    def parse_headers(
        self, lines: List[bytes]
    ) -> Tuple["CIMultiDictProxy[str]", RawHeaders]:
        headers: CIMultiDict[str] = CIMultiDict()
        # note: "raw" does not mean inclusion of OWS before/after the field value
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

            if len(bname) == 0:
                raise InvalidHeader(bname)

            # https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1-2
            if {bname[0], bname[-1]} & {32, 9}:  # {" ", "\t"}
                raise InvalidHeader(line)

            bvalue = bvalue.lstrip(b" \t")
            if len(bname) > self.max_field_size:
                raise LineTooLong(
                    "request header name {}".format(
                        bname.decode("utf8", "backslashreplace")
                    ),
                    str(self.max_field_size),
                    str(len(bname)),
                )
            name = bname.decode("utf-8", "surrogateescape")
            if not TOKENRE.fullmatch(name):
                raise InvalidHeader(bname)

            header_length = len(bvalue)

            # next line
            lines_idx += 1
            line = lines[lines_idx]

            # consume continuation lines
            continuation = line and line[0] in (32, 9)  # (' ', '\t')

            # Deprecated: https://www.rfc-editor.org/rfc/rfc9112.html#name-obsolete-line-folding
            if continuation:
                bvalue_lst = [bvalue]
                while continuation:
                    header_length += len(line)
                    if header_length > self.max_field_size:
                        raise LineTooLong(
                            "request header field {}".format(
                                bname.decode("utf8", "backslashreplace")
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
                            bname.decode("utf8", "backslashreplace")
                        ),
                        str(self.max_field_size),
                        str(header_length),
                    )

            bvalue = bvalue.strip(b" \t")
            value = bvalue.decode("utf-8", "surrogateescape")

            # https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5-5
            if "\n" in value or "\r" in value or "\x00" in value:
                raise InvalidHeader(bvalue)

            headers.add(name, value)
            raw_headers.append((bname, bvalue))

        return (CIMultiDictProxy(headers), tuple(raw_headers))


class HttpParser(abc.ABC, Generic[_MsgT]):
    lax: ClassVar[bool] = False

    def __init__(
        self,
        protocol: BaseProtocol,
        loop: asyncio.AbstractEventLoop,
        limit: int,
        max_line_size: int = 8190,
        max_field_size: int = 8190,
        timer: Optional[BaseTimerContext] = None,
        code: Optional[int] = None,
        method: Optional[str] = None,
        readall: bool = False,
        payload_exception: Optional[Type[BaseException]] = None,
        response_with_body: bool = True,
        read_until_eof: bool =