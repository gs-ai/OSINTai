#!/usr/bin/env python3
"""Entry point for the OSINTai proxy harvester.

Usage:
    python run_proxy_harvester.py --once --dry-run
    python run_proxy_harvester.py --cycles 4 --export-dir data/proxies
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from osintai.proxyharvest.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
