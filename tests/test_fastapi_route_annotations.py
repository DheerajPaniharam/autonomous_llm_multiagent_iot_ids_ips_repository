import importlib


def test_fastapi_route_modules_import() -> None:
    importlib.import_module("backend.api.loki_routes")
    importlib.import_module("backend.api.routes")
