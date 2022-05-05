"""
Hijacks common sources of entropy in order to force determinism.
Deterministic execution makes side channel trace analysis easier but possibly reduces coverage.

Note: system calls are adapted (to return constant values).
Original hooks taken from

- qiling/os/linux/syscalls.py
- qiling/os/posix/time.py

TODO Add tests to check how well this works on different platforms !
"""

import ctypes
import os
import stat
from typing import Union

from qiling.const import QL_ARCH
from qiling.os.mapper import QlFsMappedObject
from qiling.os.posix.stat import Stat
from qiling.os.posix.syscall import pack_stat_struct, AT_FDCWD, NR_OPEN

from .logger import getLogger

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
    tv_sec = 0
    tv_nsec = 0
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
    tv_sec = 0
    tv_nsec = 0
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


"""
on arm64, openssl calls faccessat to check if it has the permissions needde to manipulate the input and output files.

The original [1] qiling hook for faccessat only works with pipes, it (should ?) also work for real files.
note that we don't actually check the permissions according to
https://linux.die.net/man/2/faccessat

TODO: create an issue on the Qiling gh.

[1] qiling/os/posix/syscall/unistd.py
"""


def ql_fixed_syscall_faccessat(ql, dfd: int, filename: int, mode: int):
    access_path = ql.os.utils.read_cstring(filename)
    real_path = ql.os.path.transform_to_real_path(access_path)

    if not os.path.exists(real_path):
        regreturn = -1

    elif stat.S_ISFIFO(Stat(real_path).st_mode):
        regreturn = 0

    elif stat.S_ISREG(Stat(real_path).st_mode):
        regreturn = 0
    else:
        regreturn = -1
    if regreturn == -1:
        ql.log.debug(f"File not found or skipped: {access_path}")
    else:
        ql.log.debug(f"File found: {access_path}")

    return regreturn


"""
When testing the emulation of certain RISCV 64 bit binaries, some shared objects would fail to load.
This is because in the Qiling emulator, the transform_path return an empty path string if a file 
descriptor is already present, which causes the if condition to fail.

TODO: File a PR on the Qiling GH

The following two functions are fixed versions of the ones found in

qiling/os/posix/syscall/stat.py
"""


def transform_path(ql, dirfd: int, path: int):
    """
    Fixed version of the Qiling implementation.
    """

    dirfd = ql.unpacks(ql.pack(dirfd))
    path = ql.os.utils.read_cstring(path)

    if path.startswith("/"):
        return None, os.path.join(ql.rootfs, path)

    if dirfd == AT_FDCWD:
        return None, ql.os.path.transform_to_real_path(path)

    if 0 < dirfd < NR_OPEN:
        return (
            ql.os.fd[dirfd].fileno(),
            ql.os.fd[dirfd].name,
        )  # FIXED, return the path if fd is present


# copy of the fixed_syscall_newfstatat Qiling code, forces the usage of our fixed transform_path function
def ql_fixed_syscall_newfstatat(ql, dirfd: int, path: int, buf_ptr: int, flag: int):
    dirfd, real_path = transform_path(ql, dirfd, path)

    if os.path.exists(real_path):
        buf = pack_stat_struct(ql, Stat(real_path, dirfd))
        ql.mem.write(buf_ptr, buf)

        regreturn = 0
    else:
        regreturn = -1

    return regreturn


"""
adapted from qiling's os/unistd.py
to return the application exit code.
"""


def syscall_exit_group(ql, code: int):
    success = code == 0
    if ql.os.child_processes:
        os._exit(0)

    if ql.multithread:

        def _sched_cb_exit(cur_thread):
            ql.log.debug(f"[Thread {cur_thread.get_id()}] Terminated")
            cur_thread.stop()
            cur_thread.exit_code = code

        td = ql.os.thread_management.cur_thread
        ql.emu_stop()
        td.sched_cb = _sched_cb_exit
    else:
        ql.os.exit_code = code
        ql.os.stop()
    if not success:
        log.error("Application returned a non zero exit code.")
        exit(0)
    else:
        return 0
