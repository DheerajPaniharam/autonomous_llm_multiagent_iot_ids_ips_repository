from typing import Set, Any
import asyncio
import logging

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self) -> None:
        self._active: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._active.add(websocket)
        logger.info("WebSocket connected (%d clients)", len(self._active))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._active.discard(websocket)
        try:
            await websocket.close()
        except Exception:
            pass
        logger.info("WebSocket disconnected (%d clients)", len(self._active))

    async def broadcast(self, message: Any) -> None:
        """Send JSON-serializable message to all connected clients."""
        to_remove = []
        async with self._lock:
            clients = list(self._active)

        for ws in clients:
            try:
                await ws.send_json(message)
            except Exception:
                logger.debug("Failed to send to websocket, scheduling removal", exc_info=True)
                to_remove.append(ws)

        if to_remove:
            async with self._lock:
                for ws in to_remove:
                    self._active.discard(ws)


# Singleton instance for application-wide use
ws_manager = WebSocketManager()
