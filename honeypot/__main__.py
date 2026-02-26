import sys
from .app import run

run(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
