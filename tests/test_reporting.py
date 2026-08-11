import json

from portscanner.models import PortState, ScanMetadata, ScanResult, Target, Transport
from portscanner.reporting import (
    metadata_to_ndjson_line,
    protocol_breakdown,
    result_to_ndjson_line,
    summary_line,
    summary_to_ndjson_line,
    to_json,
)


def _result(host="10.0.0.1", port=3868, state=PortState.OPEN, protocol=None) -> ScanResult:
    return ScanResult(
        target=Target(host=host, port=port, transport=Transport.TCP),
        state=state, protocol=protocol,
        confidence="confirmed" if protocol else "",
    )


# ---------------------------------------------------------------------------
# NDJSON: every line must be fully valid standalone JSON (not part of an array)
# ---------------------------------------------------------------------------

def test_result_to_ndjson_line_is_valid_standalone_json():
    line = result_to_ndjson_line(_result(protocol="Diameter"))
    parsed = json.loads(line)  # must parse on its own with no extra context
    assert parsed["type"] == "result"
    assert parsed["host"] == "10.0.0.1"
    assert parsed["protocol"] == "Diameter"
    assert "\n" not in line  # exactly one line (an NDJSON requirement)


def test_metadata_to_ndjson_line_has_type_discriminator():
    metadata = ScanMetadata(tool_version="3.1.0", started_at="2026-01-01T00:00:00Z",
                             duration_seconds=0.0, targets_scanned=5,
                             hosts=["10.0.0.1"], ports=[3868], transports=["tcp"])
    line = metadata_to_ndjson_line(metadata)
    parsed = json.loads(line)
    assert parsed["type"] == "metadata"
    assert parsed["tool_version"] == "3.1.0"
    assert parsed["targets_scanned"] == 5


def test_summary_to_ndjson_line_counts_correctly():
    results = [
        _result(port=1, state=PortState.OPEN, protocol="Diameter"),
        _result(port=2, state=PortState.OPEN, protocol=None),  # open but without protocol confirmation
        _result(port=3, state=PortState.CLOSED),
        _result(port=4, state=PortState.FILTERED),
    ]
    line = summary_to_ndjson_line(results, duration_seconds=12.3456)
    parsed = json.loads(line)
    assert parsed["type"] == "summary"
    assert parsed["total"] == 4
    assert parsed["open"] == 2
    assert parsed["confirmed"] == 1
    assert parsed["duration_seconds"] == 12.346  # rounded to 3 decimal places


def test_ndjson_lines_are_independently_parseable_stream():
    """Simulates consuming a real NDJSON stream: each line on its own, line by line."""
    results = [_result(port=p) for p in (1, 2, 3)]
    lines = [result_to_ndjson_line(r) for r in results]
    stream_text = "\n".join(lines)

    parsed_results = [json.loads(line) for line in stream_text.split("\n")]
    assert len(parsed_results) == 3
    assert [p["port"] for p in parsed_results] == [1, 2, 3]


def test_ndjson_result_line_matches_to_dict_fields():
    r = _result(protocol="Diameter")
    ndjson_parsed = json.loads(result_to_ndjson_line(r))
    plain_dict = r.to_dict()
    for key, value in plain_dict.items():
        assert ndjson_parsed[key] == value
    assert ndjson_parsed["type"] == "result"  # the only extra field


# ---------------------------------------------------------------------------
# core reporting functions (general coverage, not just NDJSON)
# ---------------------------------------------------------------------------

def test_to_json_without_metadata_wraps_in_results_key():
    payload = json.loads(to_json([_result()]))
    assert "results" in payload
    assert "metadata" not in payload
    assert len(payload["results"]) == 1


def test_to_json_with_metadata_includes_both_keys():
    metadata = ScanMetadata(tool_version="3.1.0", started_at="now", duration_seconds=1.0,
                             targets_scanned=1)
    payload = json.loads(to_json([_result()], metadata))
    assert "metadata" in payload
    assert "results" in payload
    assert payload["metadata"]["tool_version"] == "3.1.0"


def test_summary_line_counts_open_and_confirmed():
    results = [
        _result(port=1, state=PortState.OPEN, protocol="Diameter"),
        _result(port=2, state=PortState.CLOSED),
    ]
    line = summary_line(results)
    assert "2 target" in line
    assert "1 open" in line
    assert "1 protocol" in line


def test_protocol_breakdown_empty_when_no_confirmations():
    results = [_result(state=PortState.CLOSED)]
    assert protocol_breakdown(results) == ""


def test_protocol_breakdown_counts_by_protocol_name():
    results = [
        _result(port=1, protocol="Diameter"),
        _result(port=2, protocol="Diameter"),
        _result(port=3, protocol="GTP-C"),
    ]
    breakdown = protocol_breakdown(results)
    assert "Diameter=2" in breakdown
    assert "GTP-C=1" in breakdown
