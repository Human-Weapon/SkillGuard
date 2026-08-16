"""Best-effort outbound/inbound connection observation for a process tree.

Polling a process's connection table can miss very short-lived
connections between polls. This is documented, not hidden: see spec
sections 56-58 and SECURITY.md. No packet payload is ever captured.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import psutil


@dataclass(frozen=True)
class ConnectionRecord:
    pid: int
    local_address: str
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    status: str
    seen_at_monotonic: float


def _get_connections(proc: psutil.Process):
    getter = getattr(proc, "net_connections", None) or proc.connections
    return getter(kind="inet")


def _tree_pids(root_pid: int) -> list[int]:
    try:
        root = psutil.Process(root_pid)
    except psutil.NoSuchProcess:
        return []
    pids = [root_pid]
    try:
        pids.extend(p.pid for p in root.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return pids


def snapshot_connections(pids: list[int]) -> list[ConnectionRecord]:
    now = time.monotonic()
    records: list[ConnectionRecord] = []
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            conns = _get_connections(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        for c in conns:
            laddr = c.laddr
            raddr = c.raddr if c.raddr else None
            records.append(
                ConnectionRecord(
                    pid=pid,
                    local_address=laddr.ip if laddr else "",
                    local_port=laddr.port if laddr else None,
                    remote_address=raddr.ip if raddr else None,
                    remote_port=raddr.port if raddr else None,
                    status=str(c.status),
                    seen_at_monotonic=now,
                )
            )
    return records


class NetworkMonitor:
    def __init__(self, root_pid: int, *, poll_interval: float) -> None:
        self._root_pid = root_pid
        self._poll_interval = poll_interval
        self._records: list[ConnectionRecord] = []
        self._stop = False
        self._error: BaseException | None = None
        self._thread: threading.Thread | None = None
        self._partial = False

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="skillguard-network-monitor")
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop:
                self._poll_once()
                time.sleep(self._poll_interval)
            self._poll_once()
        except BaseException as exc:  # noqa: BLE001
            self._error = exc

    def _poll_once(self) -> None:
        pids = _tree_pids(self._root_pid)
        try:
            self._records.extend(snapshot_connections(pids))
        except psutil.AccessDenied:
            self._partial = True

    def stop_and_join(self, *, timeout: float = 10.0) -> tuple[list[ConnectionRecord], bool]:
        self._stop = True
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                self._error = self._error or RuntimeError("network monitor thread did not stop in time")
        if self._error is not None:
            raise self._error
        return self._records, self._partial
