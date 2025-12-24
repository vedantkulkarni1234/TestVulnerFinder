"""
SOC-EATER v2 - Standalone Desktop GUI Application
Run with: python soc_eater_v2/desktop_app.py
"""

from __future__ import annotations

import sys
import os

# Ensure the package is in the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_eater_v2.desktop_main import main

if __name__ == "__main__":
    main()
