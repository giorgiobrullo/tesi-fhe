"""Serve the camera page with the isolated fast mixed exact-ID client."""
from pathlib import Path

from client import app as original_client
from fastapi.responses import FileResponse

UI = Path(__file__).resolve().parent
ROOT = UI.parent
if Path(original_client.__file__).resolve() != ROOT / "client/app.py":
    raise RuntimeError("The camera client must come from this isolated runtime")

app = original_client.app
root_routes = [
    route for route in app.routes
    if getattr(route, "path", None) == "/"
    and "GET" in getattr(route, "methods", set())
]
if len(root_routes) != 1:
    raise RuntimeError("Expected exactly one original GET / route")
app.router.routes.remove(root_routes[0])


@app.get("/", include_in_schema=False)
def page() -> FileResponse:
    return FileResponse(UI / "index.html")
