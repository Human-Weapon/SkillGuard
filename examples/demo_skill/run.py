"""Harmless demo fixture for the SkillGuard README quick-start.

Declares (in skillguard.capabilities.json) only filesystem.read, but
actually writes a file and spawns a subprocess -- so `skillguard audit
--dynamic` against this directory shows filesystem.write and
process.spawn as *undeclared observed* capabilities. That mismatch is the
point of this example: it is not a report of a real problem.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    Path("demo_output.txt").write_text("SkillGuard demo: this file was written by run.py\n")
    subprocess.run([sys.executable, "-c", "print('demo subprocess ran')"], check=False)
    print("demo_skill finished")


if __name__ == "__main__":
    main()
