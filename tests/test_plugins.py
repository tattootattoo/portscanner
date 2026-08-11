from unittest.mock import MagicMock, patch

from portscanner.protocols import plugins
from portscanner.protocols.base import register
from portscanner.models import Transport


def test_register_tags_builtin_source_for_core_modules():
    """Any detect function defined inside portscanner.protocols.* registers as builtin."""
    from portscanner.protocols import base as protocols_base

    async def _fake_detect(connection, timeout):
        return None

    _fake_detect.__module__ = "portscanner.protocols.some_builtin_module"
    register(name="_test_builtin_proto", transports=(Transport.TCP,))(_fake_detect)
    try:
        match = next(d for d in protocols_base.all_detectors() if d.name == "_test_builtin_proto")
        assert match.source == "builtin"
    finally:
        protocols_base._REGISTRY[:] = [
            d for d in protocols_base._REGISTRY if d.name != "_test_builtin_proto"
        ]


def test_register_tags_external_source_for_plugin_modules():
    """Simulates an external module (not under portscanner.protocols) by manually setting __module__."""
    from portscanner.protocols import base as protocols_base

    async def _fake_plugin_detect(connection, timeout):
        return None

    _fake_plugin_detect.__module__ = "some_external_plugin.detector"
    register(name="_test_plugin_proto", transports=(Transport.UDP,))(_fake_plugin_detect)
    try:
        match = next(d for d in protocols_base.all_detectors() if d.name == "_test_plugin_proto")
        assert match.source == "some_external_plugin.detector"
    finally:
        protocols_base._REGISTRY[:] = [
            d for d in protocols_base._REGISTRY if d.name != "_test_plugin_proto"
        ]


def test_discover_and_load_handles_no_plugins_gracefully():
    with patch("portscanner.protocols.plugins.entry_points", return_value=[]):
        plugins.loaded_plugins.clear()
        plugins.failed_plugins.clear()
        plugins.discover_and_load()  # must not raise even if there are no plugins at all
        assert plugins.loaded_plugins == []


def test_discover_and_load_records_successful_plugin():
    fake_ep = MagicMock()
    fake_ep.name = "fake-protocol"
    fake_ep.value = "fake_module.detector"
    fake_ep.load = MagicMock(return_value=None)

    with patch("portscanner.protocols.plugins.entry_points", return_value=[fake_ep]):
        plugins.loaded_plugins.clear()
        plugins.failed_plugins.clear()
        plugins.discover_and_load()
        assert "fake-protocol" in plugins.loaded_plugins
        assert plugins.failed_plugins == {}


def test_discover_and_load_isolates_failing_plugin():
    """A single plugin failing to load must not prevent the other plugins or the tool from working."""
    good_ep = MagicMock()
    good_ep.name = "good-protocol"
    good_ep.value = "good_module.detector"
    good_ep.load = MagicMock(return_value=None)

    bad_ep = MagicMock()
    bad_ep.name = "broken-protocol"
    bad_ep.value = "broken_module.detector"
    bad_ep.load = MagicMock(side_effect=ImportError("missing library"))

    with patch("portscanner.protocols.plugins.entry_points", return_value=[good_ep, bad_ep]):
        plugins.loaded_plugins.clear()
        plugins.failed_plugins.clear()
        plugins.discover_and_load()
        assert "good-protocol" in plugins.loaded_plugins
        assert "broken-protocol" in plugins.failed_plugins
        assert "missing library" in plugins.failed_plugins["broken-protocol"]
