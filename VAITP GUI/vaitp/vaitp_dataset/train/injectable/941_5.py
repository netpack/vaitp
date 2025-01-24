```python
    #
# The Python Imaging Library.
# $Id$
#
# PIL raster font management
#
# History:
# 1996-08-07 fl   created (experimental)
# 1997-08-25 fl   minor adjustments to handle fonts from pilfont 0.3
# 1999-02-06 fl   rewrote most font management stuff in C
# 1999-03-17 fl   take pth files into account in load_path (from Richard Jones)
# 2001-02-17 fl   added freetype support
# 2001-05-09 fl   added TransposedFont wrapper class
# 2002-03-04 fl   make sure we have a "L" or "1" font
# 2002-12-04 fl   skip non-directory entries in the system path
# 2003-04-29 fl   add embedded default font
# 2003-09-27 fl   added support for truetype charmap encodings
#
# Todo:
# Adapt to PILFONT2 format (16-bit fonts, compressed, single file)
#
# Copyright (c) 1997-2003 by Secret Labs AB
# Copyright (c) 1996-2003 by Fredrik Lundh
#
# See the README file for information on usage and redistribution.
#

import base64
import os
import sys
import warnings
from enum import IntEnum
from io import BytesIO

from . import Image
from ._util import is_directory, is_path


class Layout(IntEnum):
    BASIC = 0
    RAQM = 1


MAX_STRING_LENGTH = 1000000


try:
    from . import _imagingft as core
except ImportError as ex:
    from ._util import DeferredError

    core = DeferredError(ex)


def _string_length_check(text):
    if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
        msg = "too many characters in string"
        raise ValueError(msg)


# FIXME: add support for pilfont2 format (see FontFile.py)

# --------------------------------------------------------------------
# Font metrics format:
#       "PILfont" LF
#       fontdescriptor LF
#       (optional) key=value... LF
#       "DATA" LF
#       binary data: 256*10*2 bytes (dx, dy, dstbox, srcbox)
#
# To place a character, cut out srcbox and paste at dstbox,
# relative to the character position.  Then move the character
# position according to dx, dy.
# --------------------------------------------------------------------


class ImageFont:
    """PIL font wrapper"""

    def _load_pilfont(self, filename):
        with open(filename, "rb") as fp:
            image = None
            for ext in (".png", ".gif", ".pbm"):
                if image:
                    image.close()
                try:
                    fullname = os.path.splitext(filename)[0] + ext
                    image = Image.open(fullname)
                except Exception:
                    pass
                else:
                    if image and image.mode in ("1", "L"):
                        break
            else:
                if image:
                    image.close()
                msg = "cannot find glyph data file"
                raise OSError(msg)

            self.file = fullname

            self._load_pilfont_data(fp, image)
            image.close()

    def _load_pilfont_data(self, file, image):
        # read PILfont header
        if file.readline() != b"PILfont\n":
            msg = "Not a PILfont file"
            raise SyntaxError(msg)
        file.readline().split(b";")
        self.info = []  # FIXME: should be a dictionary
        while True:
            s = file.readline()
            if not s or s == b"DATA\n":
                break
            self.info.append(s)

        # read PILfont metrics
        data = file.read(256 * 20)

        # check image
        if image.mode not in ("1", "L"):
            msg = "invalid font image mode"
            raise TypeError(msg)

        image.load()

        self.font = Image.core.font(image.im, data)

    def getmask(self, text, mode="", *args, **kwargs):
        """
        Create a bitmap for the text.

        If the font uses antialiasing, the bitmap should have mode ``L`` and use a
        maximum value of 255. Otherwise, it should have mode ``1``.

        :param text: Text to render.
        :param mode: Used by some graphics drivers to indicate what mode the
                     driver prefers; if empty, the renderer may return either
                     mode. Note that the mode is always a string, to simplify
                     C-level implementations.

                     .. versionadded:: 1.1.5

        :return: An internal PIL storage memory instance as defined by the
                 :py:mod:`PIL.Image.core` interface module.
        """
        return self.font.getmask(text, mode)

    def getbbox(self, text, *args, **kwargs):
        """
        Returns bounding box (in pixels) of given text.

        .. versionadded:: 9.2.0

        :param text: Text to render.
        :param mode: Used by some graphics drivers to indicate what mode the
                     driver prefers; if empty, the renderer may return either
                     mode. Note that the mode is always a string, to simplify
                     C-level implementations.

        :return: ``(left, top, right, bottom)`` bounding box
        """
        _string_length_check(text)
        width, height = self.font.getsize(text)
        return 0, 0, width, height

    def getlength(self, text, *args, **kwargs):
        """
        Returns length (in pixels) of given text.
        This is the amount by which following text should be offset.

        .. versionadded:: 9.2.0
        """
        _string_length_check(text)
        width, height = self.font.getsize(text)
        return width


##
# Wrapper for FreeType fonts.  Application code should use the
# <b>truetype</b> factory function to create font objects.


class FreeTypeFont:
    """FreeType font wrapper (requires _imagingft service)"""

    def __init__(self, font=None, size=10, index=0, encoding="", layout_engine=None):
        # FIXME: use service provider instead

        self.path = font
        self.size = size
        self.index = index
        self.encoding = encoding

        if layout_engine not in (Layout.BASIC, Layout.RAQM):
            layout_engine = Layout.BASIC
            if core.HAVE_RAQM:
                layout_engine = Layout.RAQM
        elif layout_engine == Layout.RAQM and not core.HAVE_RAQM:
            warnings.warn(
                "Raqm layout was requested, but Raqm is not available. "
                "Falling back to basic layout."
            )
            layout_engine = Layout.BASIC

        self.layout_engine = layout_engine

        def load_from_bytes(f):
            self.font_bytes = f.read()
            self.font = core.getfont(
                "", size, index, encoding, self.font_bytes, layout_engine
            )

        if is_path(font):
            if sys.platform == "win32":
                font_bytes_path = font if isinstance(font, bytes) else font.encode()
                try:
                    font_bytes_path.decode("ascii")
                except UnicodeDecodeError:
                    # FreeType cannot load fonts with non-ASCII characters on Windows
                    # So load it into memory first
                    with open(font, "rb") as f:
                        load_from_bytes(f)
                    return
            self.font = core.getfont(
                font, size, index, encoding, layout_engine=layout_engine
            )
        else:
            load_from_bytes(font)

    def __getstate__(self):
        return [self.path, self.size, self.index, self.encoding, self.layout_engine]

    def __setstate__(self, state):
        path, size, index, encoding, layout_engine = state
        self.__init__(path, size, index, encoding, layout_engine)

    def getname(self):
        """
        :return