"""
Shared pytest setup: make the repository root importable so tests can
`import scanners...` / `import scripts...` without installing a package.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
