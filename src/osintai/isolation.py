"""Disposable spawn workers with wall-clock deadlines and deterministic cleanup."""

from __future__ import annotations

import math
import multiprocessing
import queue
import threading
import time


def _worker(connection, function, args, kwargs):
    try:
        connection.send((True, function(*args, **kwargs)))
    except BaseException as exc:
        connection.send((False, f"{type(exc).__name__}: {exc}"))
    finally:
        connection.close()


def isolated_call(function, *args, timeout_s=30.0, cancel_event=None, **kwargs):
    """Bound one job, including startup/IPC. Arguments must be spawn-picklable.

    A receiver thread drains large results while the parent enforces the deadline;
    joining before receiving would deadlock on a full pipe.
    """
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("worker deadline must be finite and positive")
    started = time.monotonic()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(sender, function, args, kwargs), daemon=True)
    messages = queue.Queue(maxsize=1)

    def receive():
        try:
            messages.put(receiver.recv())
        except (EOFError, OSError):
            messages.put((False, "worker exited without a result"))

    reader = None
    try:
        process.start()
        sender.close()
        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise RuntimeError("analysis job cancelled")
            remaining = timeout_s - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError(f"analysis job exceeded {timeout_s:g}s deadline")
            try:
                ok, result = messages.get(timeout=min(0.1, remaining))
                break
            except queue.Empty:
                continue
        if not ok:
            raise RuntimeError(result)
        return result
    finally:
        sender.close()
        if process.pid is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join()
            process.close()
        if reader is not None:
            reader.join(timeout=1)
        receiver.close()


async def async_isolated_call(function, *args, timeout_s=30.0):
    """Keep the event loop responsive and signal worker cleanup on cancellation."""
    import asyncio

    cancel = threading.Event()
    task = asyncio.create_task(
        asyncio.to_thread(isolated_call, function, *args, timeout_s=timeout_s, cancel_event=cancel)
    )
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        cancel.set()
        try:
            await task
        except RuntimeError:
            pass
        raise
