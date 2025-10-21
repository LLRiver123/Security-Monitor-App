"""Agent backend with WebSocket broadcast for UI integration.

This file runs a FastAPI server that:
- Starts the `sysmon_event_stream` collector in a background task
- Evaluates `suspicious_rule_structured` for each event
- Broadcasts structured alerts to connected WebSocket clients (UI)
- Exposes a POST endpoint to request `actions.perform_action`

Run: `py -3 main.py` (requires FastAPI + uvicorn)
"""
import asyncio
import json
import logging
import threading
import time
import random
from collections import deque
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

from agent.collector import sysmon_event_stream
from agent.rules import suspicious_rule_structured
from agent.actions import perform_action
from agent.ml.loader import score_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent.main")

app = FastAPI()

# In-memory alert history for demo/UI (most recent first)
ALERT_HISTORY_MAX = 500
alerts_history = deque(maxlen=ALERT_HISTORY_MAX)


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        data = json.dumps(message)
        for conn in list(self.active_connections):
            try:
                await conn.send_text(data)
            except Exception:
                self.disconnect(conn)
        # save history (keep most recent first)
        try:
            alerts_history.appendleft(message)
        except Exception:
            logger.exception("Failed to append to alert history")

manager = ConnectionManager()


@app.on_event("startup")
async def startup_event():
    logger.info("Starting background collector task...")
    # Run the blocking collector in a dedicated thread and forward events
    loop = asyncio.get_event_loop()
    t = threading.Thread(target=_collector_thread, args=(loop,), daemon=True)
    t.start()


def _demo_event(counter=0):
    # produce a simple synthetic Sysmon-like event for demo
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    idx = int(time.time() * 1000) % 100000
    imgs = [r"C:\\Windows\\System32\\notepad.exe", r"C:\\Users\\Alice\\AppData\\Local\\Temp\\evil.exe", r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]
    cmd = ["notepad.exe", "-enc SGVsbG8=", "whoami"]
    image = random.choice(imgs)
    return {
        "event_id": 1,
        "time": ts,
        "source": "demo",
        "computer": "DEMO-HOST",
        "xml": "<event/>",
        "data": {
            "Image": image,
            "ParentImage": r"C:\\Windows\\explorer.exe",
            "CommandLine": random.choice(cmd),
        },
    }


def _collector_thread(loop: asyncio.AbstractEventLoop):
    """Thread target: run blocking collector and forward events into the asyncio loop."""
    try:
        gen = sysmon_event_stream()
    except Exception:
        logger.exception("Failed to create sysmon_event_stream; switching to demo generator")
        gen = None

    if gen is None:
        # demo loop
        while True:
            ev = _demo_event()
            asyncio.run_coroutine_threadsafe(_process_event(ev), loop)
            time.sleep(1.0)
        return

    # real collector loop
    for ev in gen:
        # If generator yields an error, fall back to demo events
        if isinstance(ev, dict) and ev.get("error"):
            logger.warning("Collector error: %s; switching to demo mode", ev.get("error"))
            # switch to demo loop
            while True:
                ev2 = _demo_event()
                asyncio.run_coroutine_threadsafe(_process_event(ev2), loop)
                time.sleep(1.0)
            break
        # forward event for processing
        asyncio.run_coroutine_threadsafe(_process_event(ev), loop)


async def _process_event(event: dict):
    """Process a single event in the asyncio loop: run rules, attach ML info, and broadcast."""
    try:
        alerts = suspicious_rule_structured(event)
    except Exception:
        logger.exception("Rule evaluation failed")
        alerts = []

    # ML scoring is optional and may be expensive; keep non-blocking
    is_anom, ml_score = None, None
    try:
        # score_event may return (None, None) if ML disabled
        is_anom, ml_score = score_event(event)
    except Exception:
        logger.debug("ML scoring not available or failed")

    for alert in alerts:
        ml_info = {"is_anomaly": is_anom, "score": ml_score} if is_anom is not None else None
        payload = {
            "alert": alert,
            "event": {"event_id": event.get("event_id"), "time": event.get("time")},
            "ml": ml_info,
        }
        await manager.broadcast(payload)


async def collector_task():
    """Run the collector and broadcast alerts to UI clients."""
    # Use the sync generator in a thread to avoid blocking the event loop
    def gen():
        for e in sysmon_event_stream():
            yield e

    loop = asyncio.get_event_loop()
    for event in gen():
        # If collector yields an error, log and continue
        if "error" in event:
            logger.warning("Collector error: %s", event.get("error"))
            continue

        alerts = suspicious_rule_structured(event)
        # Attach ML anomaly info when available
        is_anom, ml_score = None, None
        try:
            is_anom, ml_score = score_event(event)
        except Exception:
            logger.exception("ML scoring failed")

        for alert in alerts:
            ml_info = {"is_anomaly": is_anom, "score": ml_score} if is_anom is not None else None
            payload = {
                "alert": alert,
                "event": {"event_id": event.get("event_id"), "time": event.get("time")},
                "ml": ml_info,
            }
            await manager.broadcast(payload)


@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; clients may send pings or action requests separately
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/action")
async def action_request(body: dict):
    """Endpoint for UI to request an action execution.

    body should contain: {"action": {...}, "fields": {...}, "confirm": true/false}
    """
    action = body.get("action")
    fields = body.get("fields")
    confirm = bool(body.get("confirm"))
    result = perform_action(action, fields=fields, confirm=confirm)
    return {"result": result}


@app.get("/alerts")
async def get_alerts(limit: int = 100):
    """Return recent alerts (most recent first)."""
    try:
        items = list(alerts_history)[:limit]
        return {"alerts": items}
    except Exception:
        logger.exception("Failed to read alerts history")
        return {"alerts": []}


if __name__ == "__main__":
    # Run uvicorn directly for simplicity
    uvicorn.run(app, host="127.0.0.1", port=8000)

