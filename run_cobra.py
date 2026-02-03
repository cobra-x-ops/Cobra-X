#!/usr/bin/env python3
"""
Simple wrapper to run Cobra X with proper encoding
"""
import sys
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Import and run the main module
sys.path.insert(0, os.path.dirname(__file__))
from cobrax import core

if __name__ == "__main__":
    import asyncio
    asyncio.run(core.main())
