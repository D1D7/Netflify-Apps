"""All long-lived objects the interfaces (Telegram, app, CLI) share, created in one place."""

from __future__ import annotations

from dataclasses import dataclass, field

from .agent import NetAgent
from .alerts import AlertLog, AlertMutes
from .config import settings
from .health import ReachabilityMonitor
from .history import LatencyHistory
from .notes import NoteStore
from .state import StateStore
from .usage import UsageTracker
from .watch import DeepMonitor


@dataclass
class Services:
    agent: NetAgent
    state: StateStore
    mutes: AlertMutes
    usage: UsageTracker
    notes: NoteStore
    history: LatencyHistory
    alerts: AlertLog
    monitor: ReachabilityMonitor = field(default_factory=ReachabilityMonitor)
    deep: DeepMonitor = field(default_factory=DeepMonitor)
    # Pending /discover results waiting for the user's "add" confirmation: token -> (candidates, credentials)
    pending_discovery: dict = field(default_factory=dict)

    @classmethod
    def create(cls, client=None) -> "Services":
        state = StateStore(settings.data_dir / "state.json")
        usage = UsageTracker(state, settings.daily_budget_usd)
        notes = NoteStore(state)
        history = LatencyHistory(settings.data_dir / "latency")
        agent = NetAgent(client=client, usage=usage, notes=notes, history=history)
        return cls(agent=agent, state=state, mutes=AlertMutes(state), usage=usage, notes=notes,
                   history=history, alerts=AlertLog(state))

    def inventory(self):
        return self.agent.inventory()
