# Example: an external plugin for portscanner (RADIUS)

This folder shows how to add a new protocol to the `portscanner` tool
**without touching its core code at all** — just a separate package
that registers itself via Python entry_points.

## Try it out

```bash
# from the root of the main portscanner project:
pip install -e .

# then install the plugin (in the same virtual environment):
pip install -e examples/example-protocol-plugin

# confirm RADIUS shows up automatically:
portscanner --list-protocols
# you should see a line like:
#   RADIUS          udp        1812, 1813      radius_plugin.detector

# an actual scan:
portscanner --host 10.0.0.5 --ports 1812,1813 --transport udp
```

## How it works, in detail

1. The plugin's `pyproject.toml` registers `radius_plugin.detector`
   under an entry_points group named `portscanner.protocols`.
2. When `portscanner.protocols` is imported (which happens
   automatically as soon as the tool runs), `protocols/plugins.py`
   looks through every installed package registered under that group,
   and imports it.
3. Simply importing `radius_plugin.detector` is enough — the
   `@register(...)` decorator inside it registers the function in the
   shared Registry, **exactly the same way the built-in protocols
   register themselves** (Diameter, SIGTRAN...). The engine
   (`engine.py`) makes no distinction at all between the two.
4. If a plugin fails to load (a missing dependency, a syntax error...),
   the tool logs a warning and keeps working normally with the rest of
   the protocols — full isolation, no single plugin can bring down the
   whole tool.

## Building your own plugin

Copy this folder as a starting point:
1. Change the package name in `pyproject.toml` and the entry point.
2. Write a `detect(connection, timeout) -> DetectionResult | None`
   function decorated with
   `@register(name=..., transports=(...), hint_ports=(...))`
   — import `DetectionResult`/`register` from
   `portscanner.protocols.base`, and `Connection` from
   `portscanner.transports.base`.
3. Install with `pip install -e .` and run `portscanner --list-protocols`
   to confirm it shows up.
