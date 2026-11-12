"""Static audit for systemd units, with drop-in provenance.

The package is import-light on purpose: the CLI, the MCP server and the test
suite all import submodules directly, and nothing here should drag in argparse.
"""

from .__about__ import __version__

__all__ = ["__version__"]
