#!/usr/bin/env python3
"""Run a command on a pty and answer its password prompt once.

Usage (in the guest): python3 pty-auth.py CMD [ARG...] <password-file

The password is the first line of stdin, so it never appears in argv. The
first prompt ending in "password:" gets it; any later prompt gets EOF, so one
call is one authentication attempt. Built for su's "Password:" prompt; sudo's
"password for USER:" does not match, so drive sudo with -S instead. Prints
what the command wrote (the password is not echoed on a pty, and is redacted
anyway) and exits with its status, or 98 if it does not finish within 30
seconds.
"""

import os
import pty
import select
import signal
import sys
import time

DEADLINE = 30


def main() -> int:
    password = sys.stdin.readline().rstrip("\n").encode()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(sys.argv[1], sys.argv[1:])
    seen = b""
    answered = 0
    end = time.monotonic() + DEADLINE
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        seen += chunk
        prompts = seen.lower().count(b"password:")
        if prompts > answered:
            answered = prompts
            time.sleep(0.2)
            os.write(fd, password + b"\n" if answered == 1 else b"\x04")
    else:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        return 98
    _, status = os.waitpid(pid, 0)
    if password:
        seen = seen.replace(password, b"<password>")
    sys.stdout.write(seen.decode(errors="replace"))
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
