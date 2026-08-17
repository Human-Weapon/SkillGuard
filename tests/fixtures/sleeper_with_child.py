"""Test fixture: spawns a long-sleeping child process, then sleeps itself.
Used to prove process-tree timeout termination kills descendants too, not
just the direct child SkillGuard launched."""

import subprocess
import sys
import time

if __name__ == "__main__":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    print(f"CHILD_PID={child.pid}", flush=True)
    time.sleep(120)
