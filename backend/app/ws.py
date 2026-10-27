"""WebSocket connection manager — broadcasts live events/incidents/stats."""

import asyncio
from typing import Any, Dict, Set

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._active: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._active.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._active.discard(ws)

    @property
    def count(self) -> int:
        return len(self._active)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        if not self._active:
            return
        async with self._lock:
            targets = list(self._active)
        async def send(ws):
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=2)
            except Exception:
                return ws
            return None
        dead = [ws for ws in await asyncio.gather(*(send(ws) for ws in targets)) if ws is not None]
        if dead:
            async with self._lock:
                for ws in dead:
                    self._active.discard(ws)


manager = ConnectionManager()
