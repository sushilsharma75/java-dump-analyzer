"""Cancellation scope for SQL work performed by a background heap worker."""
from contextvars import ContextVar
from contextlib import contextmanager
import time

cancel_requested = ContextVar('heap_cancel_requested', default=None)
analysis_deadline = ContextVar('heap_analysis_deadline', default=None)


class HeapBudgetExceeded(TimeoutError):
    """Optional analysis exhausted its shared elapsed-time budget."""


def budget_expired():
    deadline = analysis_deadline.get()
    return deadline is not None and time.monotonic() >= deadline


def check_budget():
    if budget_expired():
        raise HeapBudgetExceeded(
            'Analysis time budget reached (HEAP_ANALYSIS_MAX_SECONDS); '
            'completed histogram and findings remain available')


@contextmanager
def within_budget(deadline):
    token = analysis_deadline.set(deadline)
    try:
        check_budget()
        try:
            yield
        except Exception:
            # SQLite's progress handler reports an interrupted query; preserve
            # the budget reason instead of presenting it as a database failure.
            check_budget()
            raise
        check_budget()
    finally:
        analysis_deadline.reset(token)
