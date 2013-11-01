import unittest

import signal
import subprocess
import time

from pyptlib.util.subproc import auto_killall, create_sink, proc_is_alive, Popen, SINK
from subprocess import PIPE

# We ought to run auto_killall(), instead of manually calling proc.terminate()
# but it's not very good form to use something inside the test for itself. :p

def proc_wait(proc, wait_s):
    time.sleep(wait_s)
    proc.poll() # otherwise it doesn't exit properly

class SubprocTest(unittest.TestCase):

    def name(self):
        return self.id().split(".")[-1].replace("test_", "")

    def getMainArgs(self):
        return ["python", "-m" "pyptlib.test.util_subproc_main", self.name()]

    def spawnMain(self, cmd=None, stdout=PIPE, **kwargs):
        # spawn the main test process and wait a bit for it to initialise
        proc = Popen(cmd or self.getMainArgs(), stdout = stdout, **kwargs)
        time.sleep(0.2)
        return proc

    def readChildPid(self, proc):
        line = proc.stdout.readline()
        self.assertTrue(line.startswith("child "))
        return int(line.replace("child ", ""))

    def test_Popen_IOpassthru(self):
        """Test that output from the child passes through to the parent."""
        output = subprocess.check_output(self.getMainArgs())
        self.assertTrue(len(output) > 0)

    def test_Popen_SINK(self):
        """Test that output from the child is discarded when stdout = SINK."""
        output = subprocess.check_output(self.getMainArgs())
        self.assertTrue(len(output) == 0)

    def test_trap_sigint_multiple(self):
        """Test that adding multiple SIGINT handlers works as expected."""
        proc = self.spawnMain()
        proc.send_signal(signal.SIGINT)
        self.assertEquals("run h1\n", proc.stdout.readline())
        proc.send_signal(signal.SIGINT)
        self.assertEquals("run h2\n", proc.stdout.readline())
        self.assertEquals("run h1\n", proc.stdout.readline())
        proc.terminate()

    def test_trap_sigint_reset(self):
        """Test that resetting SIGINT handlers works as expected."""
        proc = self.spawnMain()
        proc.send_signal(signal.SIGINT)
        self.assertEquals("run h2\n", proc.stdout.readline())
        proc.terminate()

    def test_killall_kill(self):
        """Test that killall() can kill -9 a hung process."""
        proc = self.spawnMain()
        pid = proc.pid
        cid = self.readChildPid(proc)
        self.assertTrue(proc_is_alive(cid), "child did not hang")
        time.sleep(2)
        self.assertTrue(proc_is_alive(cid), "child did not ignore TERM")
        time.sleep(4)
        self.assertFalse(proc_is_alive(cid), "child was not killed by parent")
        proc.terminate()

    def test_auto_killall_2_int(self):
        """Test that auto_killall works for 2-INT signals."""
        proc = self.spawnMain()
        pid = proc.pid
        cid = self.readChildPid(proc)
        # test first signal is ignored
        proc.send_signal(signal.SIGINT)
        proc_wait(proc, 3)
        self.assertTrue(proc_is_alive(pid), "1 INT not ignored")
        self.assertTrue(proc_is_alive(cid), "1 INT not ignored")
        # test second signal is handled
        proc.send_signal(signal.SIGINT)
        proc_wait(proc, 3)
        self.assertFalse(proc_is_alive(pid), "2 INT not handled")
        self.assertFalse(proc_is_alive(cid), "2 INT not handled")

    def test_auto_killall_term(self):
        """Test that auto_killall works for TERM signals."""
        proc = self.spawnMain()
        pid = proc.pid
        cid = self.readChildPid(proc)
        # test TERM is handled
        proc.send_signal(signal.SIGTERM)
        proc_wait(proc, 3)
        self.assertFalse(proc_is_alive(pid), "TERM not handled")
        self.assertFalse(proc_is_alive(cid), "TERM not handled")

    def test_auto_killall_exit(self):
        """Test that auto_killall works on normal exit."""
        proc = self.spawnMain()
        pid = proc.pid
        cid = self.readChildPid(proc)
        # test exit is handled. main exits by itself after 1 seconds
        # exit handler takes ~2s to run, usually
        proc_wait(proc, 3)
        self.assertFalse(proc_is_alive(pid), "unexpectedly did not exit")
        self.assertFalse(proc_is_alive(cid), "parent did not kill child")

if __name__ == "__main__":
    unittest.main()
