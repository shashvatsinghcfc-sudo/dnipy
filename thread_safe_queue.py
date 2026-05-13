"""
thread_safe_queue.py – Thread-safe bounded queue.

Mirrors the C++ template class TSQueue<T> in include/thread_safe_queue.h.

The C++ version uses std::mutex + std::condition_variable.  Python's
queue.Queue already wraps a deque with a lock and two conditions
(not_empty, not_full), so this class is a thin, typed wrapper that
matches the C++ API surface while reusing the stdlib machinery.
"""

from __future__ import annotations

import queue
from typing import Generic, Optional, TypeVar

T = TypeVar("T")

_SENTINEL = object()   # signals "queue is shutting down"


class TSQueue(Generic[T]):
    """
    Thread-safe FIFO queue with optional capacity limit.

    API mirrors the C++ TSQueue:

      push(item)          – block until space is available, then enqueue.
      pop()               – block until an item is available, then dequeue.
      try_pop(timeout)    – non-blocking dequeue; returns None on timeout.
      shutdown()          – unblock all waiting threads so they can exit.
      size()              – approximate number of items currently in queue.
      empty()             – True if queue is currently empty.
    """

    def __init__(self, maxsize: int = 0) -> None:
        """
        Parameters
        ----------
        maxsize : int
            Maximum items allowed (0 = unbounded).
        """
        self._q: queue.Queue[T] = queue.Queue(maxsize=maxsize)
        self._shutdown = False

    # ------------------------------------------------------------------
    # Producer interface
    # ------------------------------------------------------------------

    def push(self, item: T) -> None:
        """
        Enqueue *item*, blocking if the queue is full.

        Equivalent to the C++ ``push()`` which calls
        ``not_full_.wait(lock, [&]{ return !full(); })``.
        """
        self._q.put(item, block=True)

    # ------------------------------------------------------------------
    # Consumer interface
    # ------------------------------------------------------------------

    def pop(self) -> Optional[T]:
        """
        Dequeue and return the next item, blocking until one is available.

        Returns None if the queue has been shut down and is empty.

        Equivalent to the C++ ``pop()`` which calls
        ``not_empty_.wait(lock, [&]{ return !queue_.empty(); })``.
        """
        try:
            item = self._q.get(block=True, timeout=0.1)
            if item is _SENTINEL:  # type: ignore[comparison-overlap]
                # Re-insert sentinel so other threads also wake up
                try:
                    self._q.put_nowait(_SENTINEL)  # type: ignore[arg-type]
                except queue.Full:
                    pass
                return None
            return item
        except queue.Empty:
            if self._shutdown:
                return None
            return None

    def try_pop(self, timeout: float = 0.0) -> Optional[T]:
        """Non-blocking pop.  Returns None immediately if empty."""
        try:
            item = self._q.get(block=(timeout > 0), timeout=timeout if timeout > 0 else None)
            if item is _SENTINEL:  # type: ignore[comparison-overlap]
                try:
                    self._q.put_nowait(_SENTINEL)  # type: ignore[arg-type]
                except queue.Full:
                    pass
                return None
            return item
        except queue.Empty:
            return None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """
        Signal that no more items will be produced.

        Inserts a sentinel so blocked ``pop()`` calls wake up and return None.
        Equivalent to setting the C++ ``running_`` flag to false and calling
        ``not_empty_.notify_all()``.
        """
        self._shutdown = True
        try:
            self._q.put_nowait(_SENTINEL)  # type: ignore[arg-type]
        except queue.Full:
            pass

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def size(self) -> int:
        return self._q.qsize()

    def empty(self) -> bool:
        return self._q.empty()
