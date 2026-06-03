#!/usr/bin/env python3
"""
main.py — ThreatHunter entry point
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gui.app import ThreatHunterApp

if __name__ == "__main__":
    app = ThreatHunterApp()
    app.mainloop()
