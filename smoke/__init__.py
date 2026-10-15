"""Opt-in live checks against a real FortiClient on a real Windows desktop.

Deliberately outside ``tests/``: nothing here is collected by
``py -3.13 -m pytest tests/``, because these scripts look at (and, for the
explicitly flagged ones, touch) the machine they run on.  See README.md.
"""
