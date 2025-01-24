from PIL import ImageFont, ImageDraw

MAX_STRING_LENGTH = 1000000

def load(filename):
    try:
        return ImageFont.load(filename)
    except Exception as e:
        raise ValueError(f"Invalid filename: {filename}") from e

def load_path(filename):
    try:
        return ImageFont.load_path(filename)
    except Exception as e:
       raise ValueError(f"Invalid filename: {filename}") from e

def truetype(font, size, index=0, encoding="", layout_engine=None):
    try:
      return ImageFont.truetype(font, size, index=index, encoding=encoding, layout_engine=layout_engine)
    except Exception as e:
      raise ValueError(f"Invalid font: {font}") from e

def load_default():
    return ImageFont.load_default()

class ImageFont:
    def __init__(self, font):
        self.font = font

    def getname(self):
        return self.font.getname()
    
    def getmetrics(self):
        return self.font.getmetrics()

    def getlength(self, text, direction=None):
        if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
            raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
        return self.font.getlength(text, direction=direction)

    def getsize(self, text, direction=None):
        if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
            raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
        return self.font.getsize(text, direction=direction)

    def getbbox(self, text, direction=None):
      if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
        raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
      return self.font.getbbox(text, direction=direction)


class FreeTypeFont(ImageFont):
    def __init__(self, font):
        super().__init__(font)

    def getname(self):
        return self.font.getname()

    def getmetrics(self):
        return self.font.getmetrics()

    def getlength(self, text, direction=None):
        if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
            raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
        return self.font.getlength(text, direction=direction)
    
    def getsize(self, text, direction=None):
        if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
          raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
        return self.font.getsize(text, direction=direction)
    
    def getbbox(self, text, direction=None):
      if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
        raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
      return self.font.getbbox(text, direction=direction)
      
class TransposedFont(ImageFont):
    def __init__(self, font):
        super().__init__(font)

    def getname(self):
      return self.font.getname()

    def getmetrics(self):
        return self.font.getmetrics()
    
    def getlength(self, text, direction=None):
      if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
            raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
      return self.font.getlength(text, direction=direction)
    
    def getsize(self, text, direction=None):
      if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
        raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
      return self.font.getsize(text, direction=direction)

    def getbbox(self, text, direction=None):
      if MAX_STRING_LENGTH is not None and len(text) > MAX_STRING_LENGTH:
        raise ValueError(f"Text length exceeds maximum allowed length: {MAX_STRING_LENGTH}")
      return self.font.getbbox(text, direction=direction)

class Layout:
    BASIC = "basic"
    RAQM = "raqm"