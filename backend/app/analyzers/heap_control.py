"""Cancellation scope for SQL work performed by a background heap worker."""
from contextvars import ContextVar

cancel_requested = ContextVar('heap_cancel_requested', default=None)
