```python
    """Test script for ftplib module."""

# Modified by Giampaolo Rodola' to test FTP class, IPv6 and TLS
# environment

import ftplib
import asyncore
import asynchat
import socket
import io
import errno
import os
import threading
import time
try:
    import ssl
except ImportError:
    ssl = None

from unittest import TestCase, skipUnless
from test import support
from test.support import threading_helper
from test.support import socket_helper
from test.support import warnings_helper
from test.support.socket_helper import HOST, HOSTv6

TIMEOUT = support.LOOPBACK_TIMEOUT
DEFAULT_ENCODING = 'utf-8'
# the dummy data returned by server over the data channel when
# RETR, LIST, NLST, MLSD commands are issued
RETR_DATA = 'abcde12345\r\n' * 1000 + 'non-ascii char \xAE\r\n'
LIST_DATA = 'foo\r\nbar\r\n non-ascii char \xAE\r\n'
NLST_DATA = 'foo\r\nbar\r\n non-ascii char \xAE\r\n'
MLSD_DATA = ("type=cdir;perm=el;unique==keVO1+ZF4; test\r\n"
             "type=pdir;perm=e;unique==keVO1+d?3; ..\r\n"
             "type=OS.unix=slink:/foobar;perm=;unique==keVO1+4G4; foobar\r\n"
             "type=OS.unix=chr-13/29;perm=;unique==keVO1+5G4; device\r\n"
             "type=OS.unix=blk-11/108;perm=;unique==keVO1+6G4; block\r\n"
             "type=file;perm=awr;unique==keVO1+8G4; writable\r\n"
             "type=dir;perm=cpmel;unique==keVO1+7G4; promiscuous\r\n"
             "type=dir;perm=;unique==keVO1+1t2; no-exec\r\n"
             "type=file;perm=r;unique==keVO1+EG4; two words\r\n"
             "type=file;perm=r;unique==keVO1+IH4;  leading space\r\n"
             "type=file;perm=r;unique==keVO1+1G4; file1\r\n"
             "type=dir;perm=cpmel;unique==keVO1+7G4; incoming\r\n"
             "type=file;perm=r;unique==keVO1+1G4; file2\r\n"
             "type=file;perm=r;unique==keVO1+1G4; file3\r\n"
             "type=file;perm=r;unique==keVO1+1G4; file4\r\n"
             "type=dir;perm=cpmel;unique==SGP1; dir \xAE non-ascii char\r\n"
             "type=file;perm=r;unique==SGP2; file \xAE non-ascii char\r\n")


class DummyDTPHandler(asynchat.async_chat):
    dtp_conn_closed = False

    def __init__(self, conn, baseclass):
        asynchat.async_chat.__init__(self, conn)
        self.baseclass = baseclass
        self.baseclass.last_received_data = ''
        self.encoding = baseclass.encoding

    def handle_read(self):
        new_data = self.recv(1024).decode(self.encoding, 'replace')
        self.baseclass.last_received_data += new_data

    def handle_close(self):
        # XXX: this method can be called many times in a row for a single
        # connection, including in clear-text (non-TLS) mode.
        # (behaviour witnessed with test_data_connection)
        if not self.dtp_conn_closed:
            self.baseclass.push('226 transfer complete')
            self.close()
            self.dtp_conn_closed = True

    def push(self, what):
        if self.baseclass.next_data is not None:
            what = self.baseclass.next_data
            self.baseclass.next_data = None
        if not what:
            return self.close_when_done()
        super(DummyDTPHandler, self).push(what.encode(self.encoding))

    def handle_error(self):
        raise Exception


class DummyFTPHandler(asynchat.async_chat):

    dtp_handler = DummyDTPHandler

    def __init__(self, conn, encoding=DEFAULT_ENCODING):
        asynchat.async_chat.__init__(self, conn)
        # tells the socket to handle urgent data inline (ABOR command)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_OOBINLINE, 1)
        self.set_terminator(b"\r\n")
        self.in_buffer = []
        self.dtp = None
        self.last_received_cmd = None
        self.last_received_data = ''
        self.next_response = ''
        self.next_data = None
        self.rest = None
        self.next_retr_data = RETR_DATA
        self.push('220 welcome')
        self.encoding = encoding
        # We use this as the string IPv4 address to direct the client
        # to in response to a PASV command.  To test security behavior.
        # https://bugs.python.org/issue43285/.
        self.fake_pasv_server_ip = '252.253.254.255'

    def collect_incoming_data(self, data):
        self.in_buffer.append(data)

    def found_terminator(self):
        line = b''.join(self.in_buffer).decode(self.encoding)
        self.in_buffer = []
        if self.next_response:
            self.push(self.next_response)
            self.next_response = ''
        cmd = line.split(' ')[0].lower()
        self.last_received_cmd = cmd
        space = line.find(' ')
        if space != -1:
            arg = line[space + 1:]
        else:
            arg = ""
        if hasattr(self, 'cmd_' + cmd):
            method = getattr(self, 'cmd_' + cmd)
            method(arg)
        else:
            self.push('550 command "%s" not understood.' %cmd)

    def handle_error(self):
        raise Exception

    def push(self, data):
        asynchat.async_chat.push(self, data.encode(self.encoding) + b'\r\n')

    def cmd_port(self, arg):
        addr = list(map(int, arg.split(',')))
        ip = '%d.%d.%d.%d' %tuple(addr[:4])
        port = (addr[4] * 256) + addr[5]
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        self.dtp = self.dtp_handler(s, baseclass=self)
        self.push('200 active data connection established')

    def cmd_pasv(self, arg):
        with socket.create_server((self.socket.getsockname()[0], 0)) as sock:
            sock.settimeout(TIMEOUT)
            port = sock.getsockname()[1]
            ip = self.fake_pasv_server_ip
            ip = ip.replace('.', ','); p1 = port / 256; p2 = port % 256
            self.push('227 entering passive mode (%s,%d,%d)' %(ip, p1, p2))
            conn, addr = sock.accept()
            self.dtp = self.dtp_handler(conn, baseclass=self)

    def cmd_eprt(self, arg):
        af, ip, port = arg.split(arg[0])[1:-1]
        port = int(port)
        s = socket.create_connection((ip, port), timeout=TIMEOUT)
        self.dtp = self.dtp_handler(s, baseclass=self)
        self.push('200 active data connection established')

    def cmd_epsv(self