from portscanner.diagnostics import gather_diagnostics, safe_max_concurrency


def test_gather_diagnostics_returns_expected_keys():
    d = gather_diagnostics()
    assert "python_version" in d
    assert "platform" in d
    assert "is_root" in d
    assert "fd_limit" in d
    assert "soft" in d["fd_limit"]
    assert "hard" in d["fd_limit"]
    for key in ("sctp", "tls", "ipv6"):
        assert key in d
        assert "available" in d[key]
        assert "detail" in d[key]
        assert isinstance(d[key]["available"], bool)


def test_gather_diagnostics_does_not_raise():
    # this function must work in any environment without raising exceptions — even if SCTP/IPv6 are unavailable
    d = gather_diagnostics()
    assert isinstance(d["python_version"], str)


def test_safe_max_concurrency_no_warning_when_within_limit():
    d = gather_diagnostics()
    soft_limit = d["fd_limit"]["soft"]
    small_request = max(1, soft_limit // 10)
    value, warning = safe_max_concurrency(small_request)
    assert value == small_request
    assert warning is None


def test_safe_max_concurrency_clamps_and_warns_when_exceeding_limit():
    d = gather_diagnostics()
    soft_limit = d["fd_limit"]["soft"]
    huge_request = soft_limit * 100
    value, warning = safe_max_concurrency(huge_request)
    assert value < huge_request
    assert value >= 1
    assert warning is not None
    assert "ulimit" in warning


def test_safe_max_concurrency_respects_reserve_margin():
    d = gather_diagnostics()
    soft_limit = d["fd_limit"]["soft"]
    value, _warning = safe_max_concurrency(soft_limit, reserve=100)
    assert value <= soft_limit - 100
