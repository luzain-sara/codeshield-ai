"""Fixed diagnostics only: never construct these from file or subprocess contents."""


class ScanError(Exception):
    """A scan could not be completed; callers must exit fail closed."""
