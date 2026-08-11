"""
protocols/plugins.py
A real plugin architecture: any external package (installed via pip,
with no relation at all to this project's own code) can add an entire
new protocol — it just needs to register itself under the
entry_points group named "portscanner.protocols" in its own
pyproject.toml, and simply installing it in the same environment
(`pip install my-ngap-plugin`) is enough for its protocol to
automatically appear in the detectors_for() list — without a single
line of change to this project's source.

Example pyproject.toml for an external package:

    [project.entry-points."portscanner.protocols"]
    ngap = "my_ngap_plugin.detector"

where my_ngap_plugin/detector.py contains a detect() function decorated
with @register(...), exactly like any internal module under
protocols/.

A single plugin failing to load (a bad import, a missing dependency...)
is logged as a warning and doesn't stop the rest of the plugins or the
tool itself from loading — full isolation.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

logger = logging.getLogger("portscanner.plugins")

ENTRY_POINT_GROUP = "portscanner.protocols"

# names of plugins that loaded successfully (shown via --list-protocols)
loaded_plugins: list[str] = []
# load errors (name -> error message) — shown in diagnostics instead of failing silently
failed_plugins: dict[str, str] = {}


def discover_and_load() -> None:
    """
    Looks for every installed package that registered itself under the
    ENTRY_POINT_GROUP group, and imports it (the import itself runs the
    @register decorator inside each module, so the import alone is
    enough to register it in the Registry).
    """
    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except Exception as e:  # older/unusual Python environments may behave differently
        logger.debug("failed to read entry_points for group %s: %s", ENTRY_POINT_GROUP, e)
        return

    for ep in eps:
        try:
            ep.load()  # the actual import — runs @register inside the module
            loaded_plugins.append(ep.name)
            logger.info("loaded external plugin: %s (%s)", ep.name, ep.value)
        except Exception as e:
            failed_plugins[ep.name] = str(e)
            logger.warning("failed to load plugin '%s' (%s): %s — skipped", ep.name, ep.value, e)
