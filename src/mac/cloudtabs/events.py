"""Bridge native Darwin notifications; no periodic scheduling."""
from __future__ import absolute_import, division, print_function, unicode_literals
import ctypes
import os
import select

_LIBRARY=ctypes.CDLL('/usr/lib/libSystem.B.dylib')


def post(name):
    if _LIBRARY.notify_post(name.encode('utf-8')):
        raise RuntimeError('Could not post Safari change notification')


class Channel(object):
    def __init__(self,name):
        descriptor=ctypes.c_int(-1)
        self.token=ctypes.c_int()
        if _LIBRARY.notify_register_file_descriptor(name.encode('utf-8'),ctypes.byref(descriptor),0,ctypes.byref(self.token)):
            raise RuntimeError('Could not register Safari change notification')
        self.fd=descriptor.value

    def wait(self):
        if len(os.read(self.fd,4))!=4:
            raise RuntimeError('Safari notification channel closed')
        # Coalesce notifications that arrived while a sync was in progress.
        while select.select([self.fd],[],[],0)[0]:
            if len(os.read(self.fd,4))!=4:
                raise RuntimeError('Safari notification channel closed')

    def close(self):
        if self.fd is not None:
            _LIBRARY.notify_cancel(self.token)
            try:os.close(self.fd)
            except OSError:pass
            self.fd=None
