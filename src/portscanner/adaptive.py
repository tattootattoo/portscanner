"""
adaptive.py
A self-adapting concurrency controller using the AIMD approach (Additive
Increase / Multiplicative Decrease) — the same principle TCP congestion
control uses. The goal: instead of guessing a fixed --concurrency number
(too high causes congestion/lots of timeouts on weak networks, too low
wastes time on strong networks), the tool watches the error rate during
the scan and automatically raises or lowers concurrency.

This file is deliberately **pure Python with no I/O** — all the
decision logic is fully testable in isolation (feed in fake error rates
and check the reaction) without a real network or even asyncio.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ConcurrencyController:
    """
    Starts at `initial`, and moves between min/max based on the
    error_rate reported after each scan batch:
      - low error_rate (< low_threshold): the network can handle more —
        additive increase (+increase_step percent of the current value).
      - high error_rate (> high_threshold): there's congestion/trouble —
        immediate multiplicative decrease (÷decrease_factor) instead of
        waiting for the problem to build up.
      - in between: hold steady (a stability zone, to avoid constant oscillation).
    """

    min_concurrency: int = 25
    max_concurrency: int = 2000
    initial_concurrency: int = 200
    low_error_threshold: float = 0.05   # under 5% errors = increase
    high_error_threshold: float = 0.20  # over 20% errors = decrease immediately
    increase_step: float = 0.5          # increase by 50% of the current value
    decrease_factor: float = 0.5        # halve on congestion

    current: int = field(init=False)
    history: list[tuple[float, int]] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if not (0 < self.min_concurrency <= self.initial_concurrency <= self.max_concurrency):
            raise ValueError(
                "must hold: 0 < min_concurrency <= initial_concurrency <= max_concurrency"
            )
        self.current = self.initial_concurrency

    def observe(self, error_rate: float) -> int:
        """Records a batch's error rate, adjusts self.current, and returns the new value."""
        if not (0.0 <= error_rate <= 1.0):
            raise ValueError(f"error_rate must be between 0 and 1, got: {error_rate}")

        if error_rate > self.high_error_threshold:
            self.current = max(self.min_concurrency, int(self.current * self.decrease_factor))
        elif error_rate < self.low_error_threshold:
            self.current = min(
                self.max_concurrency, int(self.current * (1 + self.increase_step)) + 1
            )
        # between the two thresholds: hold steady, no change

        self.history.append((error_rate, self.current))
        return self.current
