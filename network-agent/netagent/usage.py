"""AI usage and cost tracking with an optional daily budget."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from .state import StateStore

# USD per 1M tokens: (input, output, cache read, cache write). Approximate list prices;
# check https://www.anthropic.com/pricing for current values.
PRICES: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),
    "claude-opus-5": (5.00, 25.00, 0.50, 6.25),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),
    "claude-sonnet-5": (2.00, 10.00, 0.20, 2.50),
    "claude-haiku-5-5": (0.10, 0.50, 0.01, 0.125),
    "claude-opus-4-8": (5.00, 25.00, 0.50, 6.25),
    "claude-fable-5-1": (10.00, 50.00, 0.25, 12.50),
}
_DEFAULT_PRICE = PRICES["claude-opus-5-5"]
KEEP_DAYS = 62


def price_for(model: str) -> tuple[float, float, float, float]:
    if model in PRICES:
        return PRICES[model]
    # Longest known prefix wins, e.g. "claude-opus-5-5-fast" -> claude-opus-5-5
    for known in sorted(PRICES, key=len, reverse=True):
        if model.startswith(known):
            return PRICES[known]
    return _DEFAULT_PRICE


def cost_of(model: str, usage: Any) -> float:
    p_in, p_out, p_cr, p_cw = price_for(model)
    get = lambda name: int(getattr(usage, name, 0) or 0)  # noqa: E731
    return (
        get("input_tokens") * p_in
        + get("output_tokens") * p_out
        + get("cache_read_input_tokens") * p_cr
        + get("cache_creation_input_tokens") * p_cw
    ) / 1_000_000


class UsageTracker:
    KEY = "usage"

    def __init__(self, state: StateStore, daily_budget_usd: float = 0.0) -> None:
        self.state = state
        self.daily_budget_usd = daily_budget_usd

    def record(self, model: str, usage: Any, today: date | None = None) -> float:
        if usage is None:
            return 0.0
        day = (today or date.today()).isoformat()
        cost = cost_of(model, usage)

        def apply(data: dict | None) -> dict:
            data = data or {}
            entry = data.setdefault(day, {"requests": 0, "input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "cost": 0.0})
            entry["requests"] += 1
            entry["input"] += int(getattr(usage, "input_tokens", 0) or 0)
            entry["output"] += int(getattr(usage, "output_tokens", 0) or 0)
            entry["cache_read"] += int(getattr(usage, "cache_read_input_tokens", 0) or 0)
            entry["cache_write"] += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)
            entry["cost"] = round(entry["cost"] + cost, 6)
            cutoff = (date.today() - timedelta(days=KEEP_DAYS)).isoformat()
            return {k: v for k, v in data.items() if k >= cutoff}

        self.state.update(self.KEY, apply)
        return cost

    def day(self, d: date | None = None) -> dict:
        data = self.state.get(self.KEY, {}) or {}
        return data.get((d or date.today()).isoformat(), {"requests": 0, "cost": 0.0, "input": 0, "output": 0, "cache_read": 0, "cache_write": 0})

    def month_cost(self, d: date | None = None) -> float:
        prefix = (d or date.today()).strftime("%Y-%m")
        data = self.state.get(self.KEY, {}) or {}
        return round(sum(v.get("cost", 0.0) for k, v in data.items() if k.startswith(prefix)), 4)

    def over_budget(self, d: date | None = None) -> bool:
        return self.daily_budget_usd > 0 and self.day(d).get("cost", 0.0) >= self.daily_budget_usd

    def summary(self) -> str:
        t = self.day()
        y = self.day(date.today() - timedelta(days=1))
        lines = [
            "💰 **AI ხარჯი** (მიახლოებითი)",
            f"დღეს: ${t['cost']:.3f} — {t['requests']} მოთხოვნა",
            f"   tokens: in {t['input']:,} / out {t['output']:,} / cache {t['cache_read']:,}",
            f"გუშინ: ${y['cost']:.3f}",
            f"ამ თვეში: ${self.month_cost():.2f}",
        ]
        if self.daily_budget_usd > 0:
            left = max(0.0, self.daily_budget_usd - t["cost"])
            lines.append(f"დღიური ლიმიტი: ${self.daily_budget_usd:.2f} (დარჩა ${left:.2f})")
        else:
            lines.append("დღიური ლიმიტი: არ არის (NETAGENT_DAILY_BUDGET)")
        return "\n".join(lines)
