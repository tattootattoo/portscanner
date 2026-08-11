"""
protocols/__init__.py
Simply importing each protocol module here is enough to register it in
the Registry (thanks to the @register decorator in each file). To add a
new protocol to the core codebase:
1) create protocols/xxx.py with a detect() function decorated with @register
2) import it here in one line — no need to touch any other code in the project.

External protocols (plugins) are added automatically without touching
this file at all — see protocols/plugins.py.
"""

from portscanner.protocols import diameter, gtpc, gtpu, iua, m2pa, m2ua, m3ua, sip, sua, v5ua  # noqa: F401
from portscanner.protocols import plugins
from portscanner.protocols.base import all_detectors, detectors_for, port_hint

# Load any external plugins registered via entry_points — as soon as
# they're imported, any protocol inside registers itself in the
# Registry automatically (exactly like the built-in protocols, just
# from an entirely different package).
plugins.discover_and_load()

__all__ = ["all_detectors", "detectors_for", "port_hint"]
