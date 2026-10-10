import os
import sys
import json
import asyncio
import logging
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import AuditOrchestrator
from core.code_chat import AppCodeChatAssistant
from core.r2_storage import CloudflareR2Storage
from database.db import AuditDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("server")

app = FastAPI(
    title="Security Intelligence & Executive Auditor API",
    version="1.2.0",
    description="Automated static analysis, secret classification, cloud misconfiguration probing, and AI interactive chat for Android APKs and Web Applications."
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

@app.get("/favicon.ico")
def serve_favicon():
    from fastapi.responses import Response
    return Response(status_code=204)


orchestrator = AuditOrchestrator()
db = AuditDatabase()
chat_assistant = AppCodeChatAssistant()
r2_storage = CloudflareR2Storage()

# Auto-sync remote R2 scans on startup
@app.on_event("startup")
async def startup_r2_sync():
    try:
        logger.info("Initializing Cloudflare R2 storage background sync...")
        r2_storage.sync_all_to_database(db)
    except Exception as e:
        logger.debug(f"Startup R2 sync skipped: {e}")

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

class UserAccountRequest(BaseModel):
    name: str
    account_id: str
    meta: Optional[dict] = None

class ScanUrlRequest(BaseModel):
    url_or_package: str
    account_id: Optional[str] = None
    gemini_api_key: Optional[str] = None
    engine: Optional[str] = "local" # "local" or "github_cloud"
    github_token: Optional[str] = None

class ScanWebRequest(BaseModel):
    url: str
    account_id: Optional[str] = None
    gemini_api_key: Optional[str] = None
    engine: Optional[str] = "local"
    github_token: Optional[str] = None

class ChatAppRequest(BaseModel):
    scan_id: str
    query: str
    gemini_api_key: Optional[str] = None

# Background scan runner
def run_background_scan(scan_id: str, target: str, is_url: bool, is_web: bool = False, engine: str = "local", github_token: Optional[str] = None, api_key: Optional[str] = None, account_id: Optional[str] = None):
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

        if engine == "github_cloud":
            from core.github_runner import GitHubActionsRunner
            progress_callback("[CLOUD] Initializing GitHub Actions cloud dispatcher...", 5)
            runner = GitHubActionsRunner(token=github_token)
            target_type = "web" if is_web else "apk"
            report = runner.execute_cloud_audit(target, target_type=target_type, scan_id=scan_id, gemini_api_key=api_key, progress_callback=progress_callback)
        elif is_web:
            report = orchestrator.run_web_audit(target, scan_id=scan_id, progress_callback=progress_callback)
        else:
            report = orchestrator.run_audit(target, is_url=is_url, scan_id=scan_id, progress_callback=progress_callback)

        if report:
            report["scan_id"] = scan_id
            if account_id:
                report["account_id"] = account_id
            db.save_scan(report, account_id=account_id)
            try: r2_storage.upload_scan(report)
            except Exception: pass

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
        "service": "APK & Web Security Scanner & Executive Auditor",
        "jadx_ready": orchestrator.decompiler.jadx_bin is not None
    }

@app.post("/api/scan/url")
async def start_scan_url(req: ScanUrlRequest, background_tasks: BackgroundTasks):
    import uuid
    from core.target_classifier import classify_target
    target, is_web = classify_target(req.url_or_package.strip())
    if is_web:
        scan_id = f"SCAN-WEB-{uuid.uuid4().hex[:6].upper()}"
    else:
        scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

    background_tasks.add_task(
        run_background_scan,
        scan_id, target, True, is_web, req.engine or "local",
        req.github_token, req.gemini_api_key, req.account_id
    )
    return {
        "scan_id": scan_id,
        "status": "queued",
        "target": target,
        "type": "website" if is_web else "apk",
        "engine": req.engine or "local",
        "account_id": req.account_id
    }

@app.post("/api/scan/web")
async def start_scan_web(req: ScanWebRequest, background_tasks: BackgroundTasks):
    import uuid
    from core.target_classifier import classify_target
    target, _ = classify_target(req.url.strip(), explicit_type="web")
    scan_id = f"SCAN-WEB-{uuid.uuid4().hex[:6].upper()}"
    background_tasks.add_task(
        run_background_scan,
        scan_id, target, True, True, req.engine or "local",
        req.github_token, req.gemini_api_key, req.account_id
    )
    return {
        "scan_id": scan_id,
        "status": "queued",
        "target": target,
        "type": "website",
        "engine": req.engine or "local",
        "account_id": req.account_id
    }

@app.post("/api/scan/upload")
async def upload_and_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    gemini_api_key: Optional[str] = Form(None),
    account_id: Optional[str] = Form(None)
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

    background_tasks.add_task(
        run_background_scan,
        scan_id, saved_apk_path, False, False, "local",
        None, gemini_api_key, account_id
    )
    return {
        "scan_id": scan_id,
        "status": "queued",
        "filename": file.filename,
        "type": "apk",
        "account_id": account_id
    }

@app.get("/api/scans")
def list_scans(account_id: Optional[str] = Query(None)):
    return db.list_scans(account_id=account_id)

# --- User Accounts & Profiles ---
@app.post("/api/user/account")
def register_or_update_account(req: UserAccountRequest):
    user = db.save_user(req.account_id, req.name, req.meta)
    return {"status": "success", "user": user}

@app.get("/api/user/account/{account_id}")
def get_user_account(account_id: str):
    user = db.get_user(account_id)
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    scans = db.list_scans(account_id=account_id)
    user["scans"] = scans
    return user

# --- Cloudflare R2 Storage Sync ---
@app.post("/api/storage/sync")
def sync_r2_storage():
    try:
        res = r2_storage.sync_all_to_database(db)
        return JSONResponse(content=res)
    except Exception as e:
        logger.error(f"Cloudflare R2 sync failed: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@app.get("/api/storage/status")
def get_storage_status():
    return {
        "configured": r2_storage.is_configured(),
        "bucket": r2_storage.bucket_name,
        "account_id": r2_storage.account_id,
        "worker_url": r2_storage.worker_url
    }

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

def generate_report_html(scan: dict, auto_print: bool = False) -> str:
    score = scan.get("score_data", {}).get("score", 0)
    rating = scan.get("score_data", {}).get("rating", "AUDITED")
    app_info = scan.get("app_info", {})
    tech_info = scan.get("tech_info", {})
    counts = scan.get("score_data", {}).get("counts", {})
    findings = scan.get("findings", [])
    priorities = scan.get("fix_these_first", [])
    ai_engine = scan.get("ai_engine", "Gemini 2.5 Flash")
    is_web = app_info.get("is_web", False) or "SCAN-WEB" in scan.get("scan_id", "")

    color_score = "#ef4444" if score < 50 else "#f59e0b" if score < 75 else "#10b981"
    target_type_label = "🌐 Web Application Audit" if is_web else "📱 Android APK Security Audit"
    target_identifier = app_info.get("domain") or app_info.get("package") or "Target App"
    target_title = app_info.get("title") or target_identifier

    auto_print_js = "<script>window.addEventListener('load', () => { setTimeout(() => window.print(), 600); });</script>" if auto_print else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Report - {target_title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-main: #090d16;
            --bg-card: #111827;
            --bg-box: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --sev-crit: #ef4444;
            --sev-high: #f97316;
            --sev-med: #eab308;
            --sev-low: #38bdf8;
            --sev-info: #64748b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-main);
            color: var(--text-main);
            line-height: 1.55;
            padding: 24px;
        }}
        .top-action-bar {{
            max-width: 1000px;
            margin: 0 auto 20px auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 12px 20px;
            border-radius: 10px;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #2563eb;
            color: #fff;
            padding: 9px 18px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 14px;
            text-decoration: none;
            border: none;
            cursor: pointer;
            transition: 0.15s ease;
        }}
        .btn:hover {{ background: #1d4ed8; }}
        .btn-outline {{ background: transparent; border: 1px solid var(--border); color: var(--text-main); }}
        .btn-outline:hover {{ background: var(--bg-box); }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        .header-section {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 24px;
        }}
        .target-title {{ font-size: 26px; font-weight: 800; color: #fff; margin-bottom: 6px; }}
        .target-meta {{ color: var(--text-muted); font-size: 13px; display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; }}
        .tag {{ background: var(--bg-box); padding: 3px 10px; border-radius: 6px; border: 1px solid var(--border); font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
        .score-box {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-width: 140px;
            text-align: center;
        }}
        .score-circle {{
            width: 96px;
            height: 96px;
            border-radius: 50%;
            border: 6px solid {color_score};
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            font-weight: 800;
            background: rgba(0,0,0,0.3);
            margin-bottom: 6px;
        }}
        .score-circle small {{ font-size: 11px; color: var(--text-muted); font-weight: 400; }}
        .risk-rating {{ font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; color: {color_score}; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 28px;
        }}
        .stat-card {{
            background: var(--bg-box);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            text-align: center;
        }}
        .stat-count {{ font-size: 24px; font-weight: 800; margin-top: 4px; }}
        .badge-pill {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .crit {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
        .med {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }}
        .low {{ background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid #38bdf8; }}
        .info {{ background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid #64748b; }}
        h2 {{ font-size: 18px; font-weight: 700; margin: 24px 0 12px 0; color: #fff; display: flex; align-items: center; gap: 8px; }}
        .card {{
            background: #0d1322;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 14px;
            break-inside: avoid;
            page-break-inside: avoid;
        }}
        .code-box {{
            background: #040711;
            border: 1px solid #1e293b;
            padding: 12px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            overflow-x: auto;
            color: #38bdf8;
            margin: 10px 0;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 6px;
            padding: 10px 14px;
            font-size: 13px;
            color: #34d399;
            margin-top: 10px;
        }}
        .watermark {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 20px;
            margin-top: 32px;
        }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; padding: 0 !important; }}
            .top-action-bar {{ display: none !important; }}
            .report-container {{
                box-shadow: none !important;
                border: none !important;
                padding: 0 !important;
                max-width: 100% !important;
                background: #fff !important;
            }}
            .card {{
                background: #f8fafc !important;
                border: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .target-title {{ color: #000 !important; }}
            .code-box {{ background: #f1f5f9 !important; color: #0369a1 !important; border: 1px solid #cbd5e1 !important; }}
            .remediation-box {{ background: #ecfdf5 !important; color: #065f46 !important; border: 1px solid #6ee7b7 !important; }}
            .tag {{ background: #f1f5f9 !important; color: #334155 !important; border: 1px solid #cbd5e1 !important; }}
            .stat-card {{ background: #f8fafc !important; border: 1px solid #cbd5e1 !important; }}
            .stat-count {{ color: #000 !important; }}
            * {{ -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
            @page {{ size: A4; margin: 15mm; }}
        }}
    </style>
</head>
<body>
    <div class="top-action-bar">
        <div>
            <strong>🛡️ Executive Security Report</strong> &bull; <span style="color: var(--text-muted); font-size: 13px;">ID: <code>{scan.get('scan_id')}</code></span>
        </div>
        <div style="display: flex; gap: 10px;">
            <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
            <a class="btn btn-outline" href="/">✕ Back to Dashboard</a>
        </div>
    </div>

    <div class="report-container">
        <div class="header-section">
            <div>
                <div style="font-size: 12px; font-weight: 700; color: var(--primary); text-transform: uppercase; margin-bottom: 4px;">
                    {target_type_label}
                </div>
                <h1 class="target-title">{target_title}</h1>
                <div class="target-meta">
                    <span class="tag">🎯 {target_identifier}</span>
                    <span class="tag">📦 {app_info.get('version_name', 'v1.0')}</span>
                    <span class="tag">⚙️ {tech_info.get('primary_framework', 'Native / Web')}</span>
                    <span class="tag">🕒 {scan.get('timestamp', '')[:19].replace('T', ' ')} UTC</span>
                </div>
            </div>
            <div class="score-box">
                <div class="score-circle">
                    {score}
                    <small>/ 100</small>
                </div>
                <div class="risk-rating">{rating}</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="badge-pill crit">CRITICAL</span>
                <div class="stat-count" style="color: #f87171;">{counts.get('CRITICAL', 0)}</div>
            </div>
            <div class="stat-card">
                <span class="badge-pill high">HIGH</span>
                <div class="stat-count" style="color: #fb923c;">{counts.get('HIGH', 0)}</div>
            </div>
            <div class="stat-card">
                <span class="badge-pill med">MEDIUM</span>
                <div class="stat-count" style="color: #fde047;">{counts.get('MEDIUM', 0)}</div>
            </div>
            <div class="stat-card">
                <span class="badge-pill low">LOW</span>
                <div class="stat-count" style="color: #7dd3fc;">{counts.get('LOW', 0)}</div>
            </div>
            <div class="stat-card">
                <span class="badge-pill info">INFO</span>
                <div class="stat-count" style="color: #cbd5e1;">{counts.get('INFO', 0)}</div>
            </div>
        </div>

        <h2>📋 Executive Briefing</h2>
        <div class="card" style="line-height: 1.7; color: #cbd5e1;">
            <div style="font-size: 11px; color: var(--primary); font-weight: 700; margin-bottom: 8px;">
                SYNTHESIZED BY {ai_engine.upper()}
            </div>
            {scan.get('executive_summary', 'No briefing provided.').replace(chr(10), '<br>')}
        </div>

        <h2>🔥 Top Remediation Priorities</h2>
        {''.join([f'''
        <div class="card" style="border-left: 4px solid #ef4444;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong style="font-size: 15px;">#{p.get('priority', idx+1)} — {p.get('title')}</strong>
                <span class="badge-pill crit">{p.get('severity', 'CRITICAL')}</span>
            </div>
            <p style="margin: 6px 0; color: var(--text-muted); font-size: 13px;"><strong>Impact:</strong> {p.get('potential_impact')}</p>
            <p style="margin: 4px 0; color: #34d399; font-size: 13px;"><strong>Action:</strong> {p.get('action_required')}</p>
        </div>
        ''' for idx, p in enumerate(priorities)]) if priorities else '<div class="card" style="color: var(--text-muted);">🎉 No urgent critical security blockades found.</div>'}

        <h2>☁️ Cloud & Firebase Posture Diagnostics</h2>
        {''.join([f'''
        <div class="card" style="border-left: 4px solid {'#ef4444' if d.get('verdict') == 'VULNERABLE' else ('#10b981' if d.get('verdict') == 'SECURE' else '#94a3b8')};">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <strong style="font-size: 14px;">{d.get('service')} — <code>{d.get('target_url')}</code></strong>
                <span class="badge-pill {'crit' if d.get('verdict') == 'VULNERABLE' else ('low' if d.get('verdict') == 'SECURE' else 'info')}">{d.get('verdict_badge')}</span>
            </div>
            <p style="margin: 4px 0; font-size: 13px; color: var(--text-muted);">{d.get('details')}</p>
        </div>
        ''' for d in scan.get('cloud_diagnostics', [])]) if scan.get('cloud_diagnostics') else '<div class="card" style="color: var(--text-muted);">No external cloud endpoints detected for passive diagnostics.</div>'}

        <h2>🔍 Detailed Security Findings ({len(findings)})</h2>
        {''.join([f'''
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="font-size: 15px;">{f.get('title')}</strong>
                <span class="badge-pill {(f.get('severity', 'info')).lower()[:4]}">{f.get('severity')}</span>
            </div>
            <div style="color: var(--text-muted); font-size: 12px; margin-bottom: 8px;">
                📁 <strong>{f.get('category')}</strong> &bull; 📍 <code>{f.get('evidence', {}).get('file', 'Configuration')}{':' + str(f.get('evidence', {}).get('line')) if f.get('evidence', {}).get('line') else ''}</code>
            </div>
            <p style="font-size: 14px; margin-bottom: 8px;">{f.get('impact')}</p>
            {f'<pre class="code-box"><code>{f.get("evidence", {}).get("context_snippet", "")}</code></pre>' if f.get("evidence", {}).get("context_snippet") else ''}
            <div class="remediation-box">
                <strong>💡 Remediation:</strong> {f.get('remediation')}
            </div>
        </div>
        ''' for f in findings]) if findings else '<div class="card" style="color: var(--text-muted);">No security issues detected.</div>'}

        <div class="watermark">
            <p>Generated by Decryptor Automated Security Intelligence Engine &bull; Scan ID: <code>{scan.get('scan_id')}</code></p>
            <p style="font-size: 11px; margin-top: 4px;">Confidential security audit report for authorized developer remediation only.</p>
        </div>
    </div>
    {auto_print_js}
</body>
</html>
"""

# --- Interactive Code Chat Endpoints ---
@app.post("/api/chat/app")
def chat_with_app(req: ChatAppRequest):
    result = chat_assistant.answer_query(req.scan_id, req.query, gemini_api_key=req.gemini_api_key)
    return JSONResponse(content=result)

@app.get("/api/chat/prompts/{scan_id}")
def get_chat_prompts(scan_id: str):
    prompts = chat_assistant.get_suggested_prompts(scan_id)
    return JSONResponse(content={"scan_id": scan_id, "prompts": prompts})

# --- Cloud Actions Sync Endpoint ---
class CloudSyncRequest(BaseModel):
    github_token: Optional[str] = None

@app.post("/api/cloud/sync")
def sync_cloud_runs(req: CloudSyncRequest):
    try:
        from core.github_runner import GitHubActionsRunner
        token = req.github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        runner = GitHubActionsRunner(token=token)
        reports = runner.sync_recent_cloud_runs(limit=10)
        saved_count = 0
        for report in reports:
            if report and "scan_id" in report:
                db.save_scan(report)
                saved_count += 1
        return {"status": "success", "synced_count": saved_count, "total_runs_checked": len(reports)}
    except Exception as e:
        logger.error(f"Cloud sync error: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@app.get("/api/export/{scan_id}/html", response_class=HTMLResponse)
def export_html_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return HTMLResponse(content=generate_report_html(scan, auto_print=False))

@app.get("/api/export/{scan_id}/pdf", response_class=HTMLResponse)
def export_pdf_report(scan_id: str, print: bool = Query(True)):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return HTMLResponse(content=generate_report_html(scan, auto_print=print))

@app.get("/api/export/{scan_id}/json")
def export_json_report(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=scan)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)
