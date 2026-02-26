#!/usr/bin/env python3
"""
Honeypot entry point.

Usage:
    python main.py [config.yaml]
    python -m honeypot [config.yaml]   # via __main__.py
"""

import sys
from honeypot.app import run

if __name__ == "__main__":
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    run(config_path)
