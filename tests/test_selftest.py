"""
tests/test_selftest.py
Tests for the --self-test command — this is itself a real end-to-end
test (it spins up real mock servers) because that's the whole point of
selftest.py. The most important test here: confirming the function
**returns** within a reasonable time and doesn't hang — we caught a
real hanging bug while building this feature (server.wait_closed() was
hanging until it was removed).
"""

import asyncio

from portscanner.selftest import SelfTestResult, print_self_test_report, run_self_test


def test_run_self_test_completes_within_timeout():
    """The most important thing: must return within a reasonable time,
    not hang — this is exactly the bug that surfaced while building
    this feature."""
    async def _run_with_timeout():
        return await asyncio.wait_for(run_self_test(), timeout=15.0)

    results = asyncio.run(_run_with_timeout())
    assert len(results) >= 4  # at least Diameter/GTP-C/GTP-U/SIP + the SIGTRAN family


def test_run_self_test_all_local_protocols_pass():
    """Every protocol that doesn't need SCTP must actually pass in this environment."""
    async def _run():
        return await run_self_test()

    results = asyncio.run(_run())
    by_name = {r.name: r for r in results}

    for expected in ("Diameter (TCP)", "GTP-C (UDP)", "GTP-U (UDP)", "SIP/IMS (TCP)"):
        assert expected in by_name, f"missing: {expected}"
        assert by_name[expected].status == "pass", f"{expected}: {by_name[expected].detail}"


def test_run_self_test_sigtran_reports_skipped_without_sctp():
    """An environment without SCTP (like this one) must be classified skipped, not fail."""
    async def _run():
        return await run_self_test()

    results = asyncio.run(_run())
    sigtran_result = next(r for r in results if "SIGTRAN" in r.name)
    # the test environment here has no SCTP — if it ever becomes available, the result will be pass
    assert sigtran_result.status in ("skipped", "pass")


def test_print_self_test_report_returns_true_when_no_failures():
    results = [
        SelfTestResult("A", "pass"),
        SelfTestResult("B", "skipped", "environment"),
    ]
    assert print_self_test_report(results) is True


def test_print_self_test_report_returns_false_on_any_failure():
    results = [
        SelfTestResult("A", "pass"),
        SelfTestResult("B", "fail", "failure reason"),
    ]
    assert print_self_test_report(results) is False


def test_cli_self_test_exit_code_zero_on_success():
    from portscanner.cli import main as cli_main
    exit_code = cli_main(["--self-test"])
    assert exit_code == 0
