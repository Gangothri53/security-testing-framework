import sys
"""
This code snippet is used to modify the system path in order to import modules from a specific directory.

Parameters:
    None

Returns:
    None

Raises:
    None
"""
import os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../')))
