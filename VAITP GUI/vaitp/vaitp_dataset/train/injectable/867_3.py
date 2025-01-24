```python
# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
import logging
import urllib.parse
from io import BytesIO
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import treq
from canonicaljson import encode_canonical_json
from netaddr import IPAddress, IPSet
from prometheus_client import Counter
from zope.interface import implementer, provider

from OpenSSL import SSL
from OpenSSL.SSL import VERIFY_NONE
from twisted.internet import defer, error as twisted_error, protocol, ssl
from twisted.internet.interfaces import (
    IAddress,
    IHostResolution,
    IReactorPluggableNameResolver,
    IResolutionReceiver,
)
from twisted.internet.task import Cooperator
from twisted.python.failure import Failure
from twisted.web._newclient import ResponseDone
from twisted.web.client import (
    Agent,
    HTTPConnectionPool,
    ResponseNeverReceived,
    readBody,
)
from twisted.web.http import PotentialDataLoss
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent, IBodyProducer, IResponse

from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.http import QuieterFileBodyProducer, RequestTimedOutError, redact_uri
from synapse.http.proxyagent import ProxyAgent
from synapse.logging.context import make_deferred_yieldable
from synapse.logging.opentracing import set_tag, start_active_span, tags
from synapse.util import json_decoder
from synapse.util.async_helpers import timeout_deferred

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)

outgoing_requests_counter = Counter("synapse_http_client_requests", "", ["method"])
incoming_responses_counter = Counter(
    "synapse_http_client_responses", "", ["method", "code"]
)

# the type of the headers list, to be passed into the t.w.h.Headers.
# Actually we can mix str and bytes keys, but Mapping treats 'key' as invariant so
# we simplify.
RawHeaders = Union[Mapping[str, "RawHeaderValue"], Mapping[bytes, "RawHeaderValue"]]

# the value actually has to be a List, but List is invariant so we can't specify that
# the entries can either be Lists or bytes.
RawHeaderValue = Sequence[Union[str, bytes]]

# the type of the query params, to be passed into `urlencode`
QueryParamValue = Union[str, bytes, Iterable[Union[str, bytes]]]
QueryParams = Union[Mapping[str, QueryParamValue], Mapping[bytes, QueryParamValue]]


def check_against_blacklist(
    ip_address: IPAddress, ip_whitelist: Optional[IPSet], ip_blacklist: IPSet
) -> bool:
    """
    Compares an IP address to allowed and disallowed IP sets.

    Args:
        ip_address: The IP address to check
        ip_whitelist: Allowed IP addresses.
        ip_blacklist: Disallowed IP addresses.

    Returns:
        True if the IP address is in the blacklist and not in the whitelist.
    """
    if ip_address in ip_blacklist:
        if ip_whitelist is None or ip_address not in ip_whitelist:
            return True
    return False


_EPSILON = 0.00000001


def _make_scheduler(reactor):
    """Makes a schedular suitable for a Cooperator using the given reactor.

    (This is effectively just a copy from `twisted.internet.task`)
    """

    def _scheduler(x):
        return reactor.callLater(_EPSILON, x)

    return _scheduler


class _IPBlacklistingResolver:
    """
    A proxy for reactor.nameResolver which only produces non-blacklisted IP
    addresses, preventing DNS rebinding attacks on URL preview.
    """

    def __init__(
        self,
        reactor: IReactorPluggableNameResolver,
        ip_whitelist: Optional[IPSet],
        ip_blacklist: IPSet,
    ):
        """
        Args:
            reactor: The twisted reactor.
            ip_whitelist: IP addresses to allow.
            ip_blacklist: IP addresses to disallow.
        """
        self._reactor = reactor
        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist

    def resolveHostName(
        self, recv: IResolutionReceiver, hostname: str, portNumber: int = 0
    ) -> IResolutionReceiver:

        r = recv()
        addresses = []  # type: List[IAddress]

        def _callback() -> None:
            r.resolutionBegan(None)

            has_bad_ip = False
            for i in addresses:
                ip_address = IPAddress(i.host)

                if check_against_blacklist(
                    ip_address, self._ip_whitelist, self._ip_blacklist
                ):
                    logger.info(
                        "Dropped %s from DNS resolution to %s due to blacklist"
                        % (ip_address, hostname)
                    )
                    has_bad_ip = True

            # if we have a blacklisted IP, we'd like to raise an error to block the
            # request, but all we can really do from here is claim that there were no
            # valid results.
            if not has_bad_ip:
                for i in addresses:
                    r.addressResolved(i)
            r.resolutionComplete()

        @provider(IResolutionReceiver)
        class EndpointReceiver:
            @staticmethod
            def resolutionBegan(resolutionInProgress: IHostResolution) -> None:
                pass

            @staticmethod
            def addressResolved(address: IAddress) -> None:
                addresses.append(address)

            @staticmethod
            def resolutionComplete() -> None:
                _callback()

        self._reactor.nameResolver.resolveHostName(
            EndpointReceiver, hostname, portNumber=portNumber
        )

        return r


@implementer(IReactorPluggableNameResolver)
class BlacklistingReactorWrapper:
    """
    A Reactor wrapper which will prevent DNS resolution to blacklisted IP
    addresses, to prevent DNS rebinding.
    """

    def __init__(
        self,
        reactor: IReactorPluggableNameResolver,
        ip_whitelist: Optional[IPSet],
        ip_blacklist: IPSet,
    ):
        self._reactor = reactor

        # We need to use a DNS resolver which filters out blacklisted IP
        # addresses, to prevent DNS rebinding.
        self._nameResolver = _IPBlacklistingResolver(
            self._reactor, ip_whitelist, ip_blacklist
        )

    def __getattr__(self, attr: str) -> Any:
        # Passthrough to the real reactor except for the DNS resolver.
        if attr == "nameResolver":
            return self._nameResolver
        else:
            return getattr(self._reactor, attr)


class BlacklistingAgentWrapper(Agent):
    """
    An Agent wrapper which will prevent access to IP addresses being accessed
    directly (without an IP address lookup).
    """

    def __init__(
        self,
        agent: IAgent,
        ip_whitelist: Optional[IPSet] = None,
        ip_blacklist: Optional[IPSet] = None,
    ):
        """
        Args:
            agent: The Agent to wrap.
            ip_whitelist: IP addresses to allow.
            ip_blacklist: IP addresses to disallow.
        """
        self._agent = agent
        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist

    def request(
        self,
        method: bytes,
        uri: bytes,
        headers: Optional[Headers] = None,
        bodyProducer: Optional[IBodyProducer] = None,
    ) -> defer.Deferred:
        h = urllib.parse.urlparse(uri.decode("ascii"))

        try:
            ip_address = IPAddress(h.hostname)

            if check_