import os
import sys
import json
import asyncio
import logging
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel

from fastapi.staticfiles import StaticFiles

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import AuditOrchestrator
from database.db import AuditDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("server")

app = FastAPI(
    title="APK Security Intelligence & Executive Auditor API",
    version="1.0.0",
    description="Automated static analysis, secret classification, and Gemini executive reporting for Android APKs."
)

# CORS middleware for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend web directory
web_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
if os.path.exists(web_dir):
    app.mount("/static", StaticFiles(directory=web_dir), name="static")

@app.get("/", response_class=FileResponse)
def serve_index():
    index_file = os.path.join(web_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h1>Web directory not found</h1>")


orchestrator = AuditOrchestrator()
db = AuditDatabase()

# Active WebSocket connections for live scan streaming
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.debug(f"Error broadcasting to client: {e}")

manager = ConnectionManager()

class ScanUrlRequest(BaseModel):
    url_or_package: str
    gemini_api_key: Optional[str] = None

# Background scan runner
def run_background_scan(scan_id: str, target: str, is_url: bool, api_key: Optional[str] = None):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def progress_callback(msg: str, pct: int):
        payload = {"type": "progress", "scan_id": scan_id, "message": msg, "percent": pct}
        try:
            loop.run_until_complete(manager.broadcast(scan_id, payload))
        except Exception as e:
            logger.debug(f"Broadcast error: {e}")

    try:
        if api_key:
            orchestrator.ai_auditor.__init__(api_key=api_key)

        report = orchestrator.run_audit(target, is_url=is_url, progress_callback=progress_callback)
        loop.run_until_complete(manager.broadcast(scan_id, {
            "type": "complete",
            "scan_id": scan_id,
            "report": report
        }))
    except Exception as e:
        logger.error(f"Background audit failed: {e}")
        loop.run_until_complete(manager.broadcast(scan_id, {
            "type": "error",
            "scan_id": scan_id,
            "error": str(e)
        }))
    finally:
        loop.close()

@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "APK Security Scanner & Executive Auditor",
        "jadx_ready": orchestrator.decompiler.jadx_bin is not None
    }

@app.post("/api/scan/url")
async def start_scan_url(req: ScanUrlRequest, background_tasks: BackgroundTasks):
    import uuid
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    background_tasks.add_task(run_background_scan, scan_id, req.url_or_package, True, req.gemini_api_key)
    return {
        "scan_id": scan_id,
        "status": "queued",
        "target": req.url_or_package
    }

@app.post("/api/scan/upload")
async def upload_and_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    gemini_api_key: Optional[str] = Form(None)
):
    import uuid
    if not file.filename.endswith((".apk", ".xapk", ".zip")):
        raise HTTPException(status_code=400, detail="Only .apk, .xapk, or .zip files are supported.")

    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    upload_dir = os.path.join(orchestrator.workspace_dir, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    saved_apk_path = os.path.join(upload_dir, f"{scan_id}_{file.filename}")

    with open(saved_apk_path, "wb") as f:
        content = await file.read()
        f.write(content)

    background_tasks.add_task(run_background_scan, scan_id, saved_apk_path, False, gemini_api_key)
    return {
        "scan_id": scan_id,
        "status": "queued",
        "filename": file.filename
    }

@app.get("/api/scans")
def list_scans():
    return db.list_scans()

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/scans/{base_id}/diff/{new_id}")
def get_regression_diff(base_id: str, new_id: str):
    try:
        return db.compute_regression_diff(base_id, new_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Keep alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)

@app.get("/api/export/{scan_id}/html", response_class=HTMLResponse)
def export_html_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    score = scan.get("score_data", {}).get("score", 0)
    app_info = scan.get("app_info", {})
    counts = scan.get("score_data", {}).get("counts", {})
    findings = scan.get("findings", [])
    priorities = scan.get("fix_these_first", [])

    color_score = "#ef4444" if score < 50 else "#f59e0b" if score < 75 else "#10b981"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - {app_info.get('title', 'App')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 960px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 24px; }}
        .score-circle {{ width: 90px; height: 90px; border-radius: 50%; border: 6px solid {color_score}; display: flex; flex-direction: column; align-items: center; justify-content: center; font-size: 28px; font-weight: bold; }}
        .score-label {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: #7f1d1d; color: #fecaca; }}
        .badge-high {{ background: #7c2d12; color: #fed7aa; }}
        .badge-medium {{ background: #713f12; color: #fef08a; }}
        .badge-low {{ background: #1e3a5f; color: #bfdbfe; }}
        .badge-info {{ background: #1e293b; color: #94a3b8; border: 1px solid #475569; }}
        .card {{ background: #0f172a; border-radius: 8px; padding: 20px; margin-top: 16px; border: 1px solid #334155; }}
        .finding-title {{ font-size: 16px; font-weight: 600; margin-bottom: 8px; }}
        .code-box {{ background: #020617; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; color: #38bdf8; }}
        .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 20px 0; }}
        .stat-box {{ background: #0f172a; padding: 12px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0 0 8px 0;">🛡️ Executive Security Audit</h1>
                <div style="color: #94a3b8; font-size: 14px;">Package: <strong>{app_info.get('package')}</strong> | Version: {app_info.get('version_name')} | Framework: {scan.get('tech_info', {}).get('primary_framework')}</div>
            </div>
            <div class="score-circle">
                {score}
                <div class="score-label">/ 100</div>
            </div>
        </div>

        <div class="stats">
            <div class="stat-box"><span class="badge badge-critical">CRITICAL</span><div style="font-size: 20px; font-weight: bold; margin-top: 4px;">{counts.get('CRITICAL', 0)}</div></div>
            <div class="stat-box"><span class="badge badge-high">HIGH</span><div style="font-size: 20px; font-weight: bold; margin-top: 4px;">{counts.get('HIGH', 0)}</div></div>
            <div class="stat-box"><span class="badge badge-medium">MEDIUM</span><div style="font-size: 20px; font-weight: bold; margin-top: 4px;">{counts.get('MEDIUM', 0)}</div></div>
            <div class="stat-box"><span class="badge badge-low">LOW</span><div style="font-size: 20px; font-weight: bold; margin-top: 4px;">{counts.get('LOW', 0)}</div></div>
            <div class="stat-box"><span class="badge badge-info">INFO</span><div style="font-size: 20px; font-weight: bold; margin-top: 4px;">{counts.get('INFO', 0)}</div></div>
        </div>

        <h2>📋 Executive Briefing</h2>
        <div class="card" style="line-height: 1.6; color: #cbd5e1;">
            {scan.get('executive_summary', '').replace(chr(10), '<br>')}
        </div>

        <h2>🔥 Top Remediation Priorities</h2>
        {''.join([f'''
        <div class="card" style="border-left: 4px solid #ef4444;">
            <div class="finding-title">#{p.get('priority')} — {p.get('title')} <span class="badge badge-critical">{p.get('severity')}</span></div>
            <p style="margin: 4px 0; color: #94a3b8; font-size: 14px;"><strong>Impact:</strong> {p.get('potential_impact')}</p>
            <p style="margin: 4px 0; color: #10b981; font-size: 14px;"><strong>Action Required:</strong> {p.get('action_required')}</p>
        </div>
        ''' for p in priorities])}

        <h2>🔍 Detailed Security Findings ({len(findings)})</h2>
        {''.join([f'''
        <div class="card">
            <div class="finding-title">{f.get('title')} <span class="badge badge-{f.get('severity', 'info').lower()}">{f.get('severity')}</span></div>
            <p style="color: #94a3b8; font-size: 13px; margin: 4px 0;"><strong>Category:</strong> {f.get('category')} | <strong>Location:</strong> {f.get('evidence', {}).get('file', 'N/A')}:{f.get('evidence', {}).get('line', '')}</p>
            <p style="color: #cbd5e1; font-size: 14px;">{f.get('impact')}</p>
            {f'<pre class="code-box"><code>{f.get("evidence", {}).get("context_snippet", "")}</code></pre>' if f.get("evidence", {}).get("context_snippet") else ''}
            <div style="background: #020617; padding: 8px 12px; border-radius: 4px; color: #34d399; font-size: 13px;">
                <strong>Remediation:</strong> {f.get('remediation')}
            </div>
        </div>
        ''' for f in findings])}
    </div>
</body>
</html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)
