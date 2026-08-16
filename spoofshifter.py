#!/usr/bin/env python3
"""SpoofShifter - advanced DNS spoofing for authorized penetration testing.

Thin entry point; all logic lives in the importable ``spoofshifter`` package.

Usage (as root on Linux):
    sudo python3 spoofshifter.py -d www.google.com@10.0.2.4
    sudo python3 spoofshifter.py --help
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from spoofshifter.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
