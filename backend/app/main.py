"""
Nexora backend — FastAPI app.

Run (local, SQLite):   uvicorn backend.app.main:app --reload --port 8000
Docs:                  http://localhost:8000/docs
WebSocket:             ws://localhost:8000/ws/events

Serves the built frontend (frontend/dist) at / when present, so a single
container can host the whole app.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from . import bootstrap  # noqa: F401  (sets sys.path first)
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import init_db
from .pipeline import pipeline
from .ws import manager
from .routers import events, incidents, simulate, metrics

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await pipeline.start()
    yield
    await pipeline.stop()


app = FastAPI(title="Nexora Security Monitoring API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=settings.cors_list != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(simulate.router, prefix="/api")
app.include_router(metrics.router, prefix="/api")


@app.get("/api")
def api_root():
    return {
        "name": "Nexora Security Monitoring API",
        "version": "1.0.0",
        "endpoints": ["/api/events", "/api/incidents", "/api/metrics",
                      "/api/simulate/attack/{type}", "/ws/events", "/docs"],
    }


@app.websocket("/ws/events")
async def ws_events(ws: WebSocket):
    await manager.connect(ws)
    # Send a snapshot so a just-connected client isn't blank.
    await ws.send_json({"type": "stats", "data": pipeline.stats()})
    try:
        while True:
            # We don't expect client messages; this keeps the socket open and
            # detects disconnects.
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)


# ── Serve the built SPA (if present) ─────────────────────────────────────────
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        if full_path.startswith(("api", "ws", "docs", "openapi.json")):
            return JSONResponse({"detail": "Not found"}, status_code=404)
        candidate = (FRONTEND_DIST / full_path).resolve()
        if candidate.is_relative_to(FRONTEND_DIST.resolve()) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
else:
    @app.get("/")
    def root_hint():
        return {
            "message": "Nexora backend running. Frontend build not found; run the "
                       "Vite dev server, or build it into frontend/dist.",
            "api": "/api", "docs": "/docs",
        }
