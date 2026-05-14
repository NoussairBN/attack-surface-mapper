#!/usr/bin/env python3
"""Attack Surface Mapper - Main Entry Point."""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from ui.cli import main

if __name__ == "__main__":
    main()