"""
Hijacks common sources of entropy in order to force determinism.
Deterministic execution makes side channel trace analysis easier but possibly reduces coverage.

Note: system calls are adapted (to return constant values).
Original hooks taken from

- qiling/os/linux/syscalls.py
- qiling/os/posix/time.py

TODO Add tests to check how well this works on different platforms !
"""

from typing import Union
from qiling.os.mapper import QlFsMappedObject
from .logger import getLogger
from qiling.const import QL_ARCH
import ctypes

log = getLogger()

"""
Possible sources of randomness in on most unix like systems:
- /dev/urandom
- /dev/random
- /dev/arandom
"""


class device_random(QlFsMappedObject):
    def read(self, size):
        return b"\xAA"

    def fstat(self):
        return -1

    def close(self):
        return 0


"""
Intercept time related functions (201,403,..)
"""


def const_time(ql):
    return 42


"""
Intercept getrandom
"""


def const_getrandom(ql, buf: int, buflen: int, flags: int):
    try:
        data = bytes("A" * buflen, "utf-8")
        ql.mem.write(buf, data)
    except Exception as e:
        log.debug(e)
        retval = -1
    else:
        ql.log.debug(f'getrandom() CONTENT: {data.hex(" ")}')
        retval = len(data)

    return retval


class timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_uint64), ("tv_nsec", ctypes.c_int64)]

    _pack_ = 8


class timespec32(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_uint32), ("tv_nsec", ctypes.c_int32)]

    _pack_ = 4


"""
Intercept gettime()
"""


def const_clock_gettime(
    ql, clock_gettime_clock_id, clock_gettime_timespec, *args, **kw
):
    tv_sec = 42
    tv_nsec = 42
    tp: Union[timespec32, timespec]
    if ql.arch.type == QL_ARCH.X8664:
        tp = timespec(tv_sec=tv_sec, tv_nsec=tv_nsec)
    else:
        tp = timespec32(tv_sec=tv_sec, tv_nsec=tv_nsec)
    ql.mem.write(clock_gettime_timespec, bytes(tp))

    ql.log.debug(
        "clock_gettime(clock_id = %d, timespec = 0x%x)"
        % (clock_gettime_clock_id, clock_gettime_timespec)
    )

    return 0


"""
Intercept gettimeofday()
"""


def const_clock_gettimeofday(ql, gettimeofday_tv, gettimeofday_tz, *args, **kw):
    tv_sec = 42
    tv_nsec = 42
    tp: Union[timespec32, timespec]
    if ql.arch.type == QL_ARCH.X8664:
        tp = timespec(tv_sec=tv_sec, tv_nsec=tv_nsec)
    else:
        tp = timespec32(tv_sec=tv_sec, tv_nsec=tv_nsec)

    if gettimeofday_tv != 0:
        ql.mem.write(gettimeofday_tv, bytes(tp))
    if gettimeofday_tz != 0:
        ql.mem.write(gettimeofday_tz, b"\x00" * 8)
    regreturn = 0
    return regreturn
