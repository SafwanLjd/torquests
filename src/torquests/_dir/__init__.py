"""The directory layer: from raw Tor directory documents to a node database.

This package parses the microdescriptor-flavor consensus and microdescriptors,
verifies consensus signatures against the directory authorities, and selects
bandwidth-weighted paths (guard / middle / exit) from the resulting relay set.
"""
