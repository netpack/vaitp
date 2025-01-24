# -*- coding: utf-8 -*-

from threading import Lock

from ..utils.struct.lock import lock
from .browser import Browser
from .bucket import Bucket
from .cookie_jar import CookieJar
from .http.http_request import HTTPRequest
from .xdcc.request import XDCCRequest
import logging
import copy

DEFAULT_REQUEST = None


class RequestFactory:
    def __init__(self, core):
        self.lock = Lock()
        self.pyload = core
        self._ = core._
        self.bucket = Bucket()
        self.update_bucket()
        self.cookiejars = {}
        self.logger = logging.getLogger(__name__)


        global DEFAULT_REQUEST
        if not DEFAULT_REQUEST:
            DEFAULT_REQUEST = self

    def iface(self):
        return self.pyload.config.get("download", "interface")

    @lock
    def get_request(self, plugin_name, account=None, type="HTTP", **kwargs):
        options = self.get_options()
        options.update(kwargs)

        if type == "XDCC":
            req = XDCCRequest(self.bucket, options)

        else:
            req = Browser(self.bucket, options)

            if account:
                cj = self.get_cookie_jar(plugin_name, account)
            else:
                cj = CookieJar(plugin_name)

            req.set_cookie_jar(cj)

        return req

    def get_http_request(self, **kwargs):
        """
        returns a http request, dont forget to close it !
        """
        options = self.get_options()
        options.update(kwargs)
        return HTTPRequest(CookieJar(None), options)

    def get_url(self, *args, **kwargs):
        """
        see HTTPRequest for argument list.
        """
        options = self.get_options()
        with HTTPRequest(None, options) as h:
            try:
                rep = h.load(*args, **kwargs)
            except Exception:
                self.logger.exception("Error during HTTP request")
                return None
        return rep

    def get_cookie_jar(self, plugin_name, account=None):
        key = (plugin_name, account)
        if key in self.cookiejars:
            return self.cookiejars[key]

        cj = CookieJar(plugin_name, account)
        self.cookiejars[key] = cj
        return cj

    def get_proxies(self):
        """
        returns a proxy list for the request classes.
        """
        if not self.pyload.config.get("proxy", "enabled"):
            return {}
        
        proxy_type = self.pyload.config.get("proxy", "type").lower()
        
        username = self.pyload.config.get("proxy", "username")
        if not username or username.lower() == "none":
            username = None

        pw = self.pyload.config.get("proxy", "password")
        if not pw or pw.lower() == "none":
            pw = None

        return {
            "type": proxy_type,
            "host": self.pyload.config.get("proxy", "host"),
            "port": self.pyload.config.get("proxy", "port"),
            "username": username,
            "password": pw,
        }


    def get_options(self):
        """
        returns options needed for pycurl.
        """
        options =  {
            "interface": self.iface(),
            "proxies": self.get_proxies(),
            "ipv6": self.pyload.config.get("download", "ipv6"),
            "ssl_verify": self.pyload.config.get("general", "ssl_verify"),
        }
        return copy.deepcopy(options)

    def update_bucket(self):
        """
        set values in the bucket according to settings.
        """
        if not self.pyload.config.get("download", "limit_speed"):
            self.bucket.set_rate(-1)
        else:
            self.bucket.set_rate(self.pyload.config.get("download", "max_speed") << 10)


def get_url(*args, **kwargs):
    if DEFAULT_REQUEST:
        return DEFAULT_REQUEST.get_url(*args, **kwargs)
    return None


def get_request(*args, **kwargs):
    if DEFAULT_REQUEST:
       return DEFAULT_REQUEST.get_http_request(*args, **kwargs)
    return None
