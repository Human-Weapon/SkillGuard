"""Test fixture for SG2-002: this process (the direct child SkillGuard
launches) spawns a descendant that inherits stdout/stderr -- the default
subprocess.Popen behavior when stdout/stderr are not redirected -- and
then EXITS QUICKLY itself, while the descendant keeps running (and keeps
the inherited pipe write-end(s) open) far longer than any test timeout.

argv[1]: which stream(s) the descendant inherits/holds open:
    "both" (default), "stdout", or "stderr".
argv[2]: "grandchild" to add one more level of indirection -- the direct
    child spawns an intermediate that itself exits quickly after spawning
    the real long-sleeping holder, so the pipe is held by a GRANDCHILD of
    the direct child, not a child.

Prints CHILD_PID=<pid> (and, for the grandchild variant, also
GRANDCHILD_PID=<pid>) before exiting so the test can identify every PID
it needs to confirm was cleaned up.
"""

import subprocess
import sys
import time

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"
    depth = sys.argv[2] if len(sys.argv) > 2 else "child"

    kwargs: dict[str, object] = {}
    if mode == "stdout":
        kwargs["stderr"] = subprocess.DEVNULL
    elif mode == "stderr":
        kwargs["stdout"] = subprocess.DEVNULL

    if depth == "grandchild":
        inner = (
            "import subprocess, sys, time;"
            "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']);"
            "print(f'GRANDCHILD_PID={gc.pid}', flush=True);"
        )
        holder = subprocess.Popen([sys.executable, "-c", inner], **kwargs)
        # subprocess.Popen() returns as soon as the OS accepts the new
        # process, not once it has actually run any of its own code --
        # give the intermediate process (a brand-new Python interpreter)
        # enough wall-clock time to start, spawn the real grandchild
        # holder, and flush GRANDCHILD_PID before THIS process exits.
        time.sleep(0.5)
    else:
        holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], **kwargs)
        time.sleep(0.05)

    print(f"CHILD_PID={holder.pid}", flush=True)
    # This process (the direct child) exits here -- quickly, well within
    # any reasonable test timeout -- while `holder` (and, in the
    # grandchild variant, ITS child) keeps running and keeps holding
    # whichever stream(s) it inherited.
