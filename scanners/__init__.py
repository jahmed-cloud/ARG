"""
Azure Resource Guardian — scanner framework and built-in scanners.

Importing any scanner submodule triggers self-registration into the
global ScannerRegistry via the @register_scanner decorator (see
scanners/base/base_scanner.py). The worker imports this package's
submodules explicitly at startup to populate the registry — see
workers/scan_worker.py for the import list.
"""
