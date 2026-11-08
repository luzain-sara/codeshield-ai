"""Argument diagnostics must never echo potentially sensitive user input."""

import argparse


class SafeArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        self.exit(2, f"{self.prog}: invalid arguments; use --help for supported options.\n")
