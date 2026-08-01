"""Module entry point: enforces the Python 3.13 floor before dispatching to cli."""

import sys

REQUIRED_PYTHON = (3, 13)

_MIN = ".".join(str(part) for part in REQUIRED_PYTHON)


def _guard() -> int:
    if sys.version_info[:2] < REQUIRED_PYTHON:
        running = ".".join(str(part) for part in sys.version_info[:3])
        sys.stderr.write(
            f"retoolkit requires Python {_MIN} or newer; running Python {running}. "
            f"Install Python {_MIN} and invoke with `py -3.13 -m retoolkit`.\n"
        )
        return 5

    from retoolkit.cli import main

    return main()


if __name__ == "__main__":
    sys.exit(_guard())
