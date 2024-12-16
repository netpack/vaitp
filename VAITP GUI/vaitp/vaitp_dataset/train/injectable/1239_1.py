import asyncio

class FixedSelectorSocketTransport(asyncio.SelectorSocketTransport):
    def writelines(self, buffers):
        if self._high_water_mark is not None and self._buffer_size >= self._high_water_mark:
            self._protocol.drain()  #Explicitly call drain to prevent buffer overflow

        super().writelines(buffers)