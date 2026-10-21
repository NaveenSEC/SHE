"""Entry point for "python -m she_memory_update" (same as the she-update command)."""

import sys  # sys.exit passes the return code to the shell

from .cli import main  # the command line interface

sys.exit(main())  # run the CLI and exit with its return code
