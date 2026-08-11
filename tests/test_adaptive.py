import pytest

from portscanner.adaptive import ConcurrencyController


def test_initial_value_is_initial_concurrency():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=100)
    assert c.current == 100


def test_invalid_bounds_raise():
    with pytest.raises(ValueError):
        ConcurrencyController(min_concurrency=100, max_concurrency=50, initial_concurrency=75)
    with pytest.raises(ValueError):
        ConcurrencyController(min_concurrency=10, max_concurrency=100, initial_concurrency=200)


def test_low_error_rate_increases_concurrency():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=100)
    new_value = c.observe(0.0)
    assert new_value > 100


def test_high_error_rate_decreases_concurrency():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=100)
    new_value = c.observe(0.5)
    assert new_value < 100


def test_moderate_error_rate_keeps_steady():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=100,
                               low_error_threshold=0.05, high_error_threshold=0.20)
    new_value = c.observe(0.10)  # between the two thresholds
    assert new_value == 100


def test_never_exceeds_max_concurrency():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=150, initial_concurrency=100)
    for _ in range(20):
        c.observe(0.0)  # repeated increase
    assert c.current <= 150


def test_never_drops_below_min_concurrency():
    c = ConcurrencyController(min_concurrency=50, max_concurrency=1000, initial_concurrency=100)
    for _ in range(20):
        c.observe(1.0)  # repeated decrease
    assert c.current >= 50


def test_invalid_error_rate_raises():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=100)
    with pytest.raises(ValueError):
        c.observe(1.5)
    with pytest.raises(ValueError):
        c.observe(-0.1)


def test_history_records_each_observation():
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=100)
    c.observe(0.0)
    c.observe(0.5)
    assert len(c.history) == 2
    assert c.history[0][0] == 0.0
    assert c.history[1][0] == 0.5


def test_recovers_after_congestion_clears():
    """A realistic scenario: temporary congestion (lots of errors) then recovery — it grows again."""
    c = ConcurrencyController(min_concurrency=10, max_concurrency=1000, initial_concurrency=200)
    c.observe(0.8)  # heavy congestion
    congested_value = c.current
    assert congested_value < 200
    for _ in range(5):
        c.observe(0.0)  # the network stabilized
    assert c.current > congested_value
