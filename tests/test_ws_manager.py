from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from backend.api.ws_manager import WebSocketManager


@pytest.mark.asyncio
async def test_connect_and_disconnect_adds_and_removes_clients() -> None:
    manager = WebSocketManager()
    websocket = AsyncMock()

    await manager.connect(websocket)

    websocket.accept.assert_awaited_once()
    assert websocket in manager._active

    await manager.disconnect(websocket)

    websocket.close.assert_awaited_once()
    assert websocket not in manager._active


@pytest.mark.asyncio
async def test_broadcast_sends_json_to_all_connected_clients_and_removes_invalid_ones() -> None:
    manager = WebSocketManager()
    websocket_1 = AsyncMock()
    websocket_2 = AsyncMock()
    websocket_2.send_json.side_effect = RuntimeError("broken websocket")

    await manager.connect(websocket_1)
    await manager.connect(websocket_2)

    await manager.broadcast({"type": "test", "payload": {"value": 1}})

    websocket_1.send_json.assert_awaited_once_with({"type": "test", "payload": {"value": 1}})
    websocket_2.send_json.assert_awaited_once_with({"type": "test", "payload": {"value": 1}})
    assert websocket_2 not in manager._active
    assert websocket_1 in manager._active
