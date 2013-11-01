"""Common tasks for managing child processes.

To have child processes actually be managed by this module, you should use
the Popen() here rather than subprocess.Popen() directly.

Some parts do not yet work fully on windows (sending/trapping signals).
"""

import atexit
import inspect
import os
import signal
import subprocess
import sys
import time

mswindows = (sys.platform == "win32")

_CHILD_PROCS = []
# TODO(infinity0): add functionality to detect when any child dies, and
# offer different response strategies for them (e.g. restart the child? or die
# and kill the other children too).

SINK = object()

# get default args from subprocess.Popen to use in subproc.Popen
a = inspect.getargspec(subprocess.Popen.__init__)
_Popen_defaults = zip(a.args[-len(a.defaults):],a.defaults); del a
if mswindows:
    # required for os.kill() to work
    tmp = dict(_Popen_defaults)
    tmp['creationflags'] |= subprocess.CREATE_NEW_PROCESS_GROUP
    _Popen_defaults = tmp.items()
    del tmp

class Popen(subprocess.Popen):
    """Wrapper for subprocess.Popen that tracks every child process.

    See the subprocess module for documentation.

    Additionally, you may use subproc.SINK as the value for either of the
    stdout, stderr arguments to tell subprocess to discard anything written
    to those channels.
    """

    def __init__(self, *args, **kwargs):
        kwargs = dict(_Popen_defaults + kwargs.items())
        for f in ['stdout', 'stderr']:
            if kwargs[f] is SINK:
                kwargs[f] = create_sink()
        # super() does some magic that makes **kwargs not work, so just call
        # our super-constructor directly
        subprocess.Popen.__init__(self, *args, **kwargs)
        _CHILD_PROCS.append(self)

    # TODO(infinity0): perhaps replace Popen.std* with wrapped file objects
    # that don't buffer readlines() et. al. Currently one must avoid these and
    # use while/readline(); see man page for "python -u" for more details.

def create_sink():
    return open(os.devnull, "w", 0)


if mswindows:
    # from http://www.madebuild.org/blog/?p=30
    from ctypes import byref, windll
    from ctypes.wintypes import DWORD

    # GetExitCodeProcess uses a special exit code to indicate that the process is
    # still running.
    _STILL_ACTIVE = 259

    def proc_is_alive(pid):
        """Check if a pid is still running."""

        handle = windll.kernel32.OpenProcess(1, 0, pid)
        if handle == 0:
            return False

        # If the process exited recently, a pid may still exist for the handle.
        # So, check if we can get the exit code.
        exit_code = DWORD()
        is_running = (
            windll.kernel32.GetExitCodeProcess(handle, byref(exit_code)) == 0)
        windll.kernel32.CloseHandle(handle)

        # See if we couldn't get the exit code or the exit code indicates that the
        # process is still running.
        return is_running or exit_code.value == _STILL_ACTIVE

else:
    # adapted from http://stackoverflow.com/questions/568271/check-if-pid-is-not-in-use-in-python
    import errno

    def proc_is_alive(pid):
        """Check if a pid is still running."""
        try:
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.EPERM:
                return True
            if e.errno == errno.ESRCH:
                return False
            raise # something else went wrong
        else:
            return True


_SIGINT_RUN = {}
def trap_sigint(handler, ignoreNum=0):
    """Register a handler for an INT signal.

    Successive traps registered via this function are cumulative, and override
    any previous handlers registered using signal.signal(). To reset these
    cumulative traps, call signal.signal() with another (maybe dummy) handler.

    Args:
        handler: a signal handler; see signal.signal() for details
        ignoreNum: number of signals to ignore before activating the handler,
            which will be run on all subsequent signals.
    """
    prev_handler = signal.signal(signal.SIGINT, _run_sigint_handlers)
    if prev_handler != _run_sigint_handlers:
        _SIGINT_RUN.clear()
    _SIGINT_RUN.setdefault(ignoreNum, []).append(handler)

_intsReceived = 0
def _run_sigint_handlers(signum=0, sframe=None):
    global _intsReceived
    _intsReceived += 1

    # code snippet adapted from atexit._run_exitfuncs
    exc_info = None
    for i in xrange(_intsReceived).__reversed__():
        for handler in _SIGINT_RUN.get(i, []).__reversed__():
            try:
                handler(signum, sframe)
            except SystemExit:
                exc_info = sys.exc_info()
            except:
                import traceback
                print >> sys.stderr, "Error in subproc._run_sigint_handlers:"
                traceback.print_exc()
                exc_info = sys.exc_info()

    if exc_info is not None:
        raise exc_info[0], exc_info[1], exc_info[2]


_isTerminating = False
def killall(cleanup=lambda:None, wait_s=16):
    """Attempt to gracefully terminate all child processes.

    All children are told to terminate gracefully. A waiting period is then
    applied, after which all children are killed forcefully. If all children
    terminate before this waiting period is over, the function exits early.

    Args:
        cleanup: Run after all children are dead. For example, if your program
                does not automatically terminate after this, you can use this
                to signal that it should exit. In particular, Twisted
                applications ought to use this to call reactor.stop().
        wait_s: Time in seconds to wait before trying to kill children.
    """
    # TODO(infinity0): log this somewhere, maybe
    global _isTerminating, _CHILD_PROCS
    if _isTerminating: return
    _isTerminating = True
    # terminate all
    for proc in _CHILD_PROCS:
        if proc.poll() is None:
            proc.terminate()
    # wait and make sure they're dead
    for i in xrange(wait_s):
        _CHILD_PROCS = [proc for proc in _CHILD_PROCS
                        if proc.poll() is None]
        if not _CHILD_PROCS: break
        time.sleep(1)
    # if still existing, kill them
    for proc in _CHILD_PROCS:
        if proc.poll() is None:
            proc.kill()
    time.sleep(0.5)
    # reap any zombies
    for proc in _CHILD_PROCS:
        proc.poll()
    cleanup()

def auto_killall(ignoreNumSigInts=0, *args, **kwargs):
    """Automatically terminate all child processes on exit.

    Args:
        ignoreNumSigInts: this number of INT signals will be ignored before
            attempting termination. This will be attempted unconditionally in
            all other cases, such as on normal exit, or on a TERM signal.
        *args, **kwargs: See killall().
    """
    killall_handler = lambda signum, sframe: killall(*args, **kwargs)
    trap_sigint(killall_handler, ignoreNumSigInts)
    signal.signal(signal.SIGTERM, killall_handler)
    atexit.register(killall, *args, **kwargs)
