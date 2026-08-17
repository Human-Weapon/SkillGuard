"""Test fixture: prints its first argv value to stdout, verbatim."""

import sys

if __name__ == "__main__":
    print(sys.argv[1])
