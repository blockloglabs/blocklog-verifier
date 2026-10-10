#!/usr/bin/env python3
"""
Entry point for executing the verifier module directly via:
    python -m verifier <receipt.json>
"""
import sys
from verifier.cli import main

if __name__ == "__main__":
    main()
