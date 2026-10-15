"""Offline, deterministic threat-hunting portfolio lab (synthetic telemetry only)."""

from .engine import HuntInputError, run_hunt

__all__ = ["HuntInputError", "run_hunt"]
