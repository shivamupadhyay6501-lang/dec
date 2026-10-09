import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from core.orchestrator import AuditOrchestrator
from server.main import generate_report_html

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloud_runner")

def main():
    target = os.environ.get("TARGET_INPUT", "https://example.com").strip()
    api_key = os.environ.get("API_KEY_INPUT") or os.environ.get("GEMINI_API_KEY") or None
    is_web = target.startswith(("http://", "https://")) and "play.google.com/store/apps" not in target

    logger.info(f"Starting GitHub Cloud Audit for target: '{target}' (Type: {'Website' if is_web else 'Android App'})")

    os.makedirs("output_reports", exist_ok=True)
    orchestrator = AuditOrchestrator()

    if api_key:
        try:
            orchestrator.ai_auditor.__init__(api_key=api_key)
        except Exception as e:
            logger.warning(f"Failed to set Gemini API key: {e}")

    if is_web:
        report = orchestrator.run_web_audit(target)
    else:
        report = orchestrator.run_audit(target, is_url=True)

    # 1. Save JSON Report
    json_path = "output_reports/report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Saved JSON report to {json_path}")

    # 1.5. Persist directly to Cloudflare R2
    try:
        from core.r2_storage import CloudflareR2Storage
        r2 = CloudflareR2Storage()
        r2.upload_scan(report)
        logger.info("Successfully synced audit report to Cloudflare R2 from cloud runner.")
    except Exception as e:
        logger.debug(f"Cloud runner R2 sync skipped: {e}")

    # 2. Save Standalone HTML Printable Report
    html_path = "output_reports/report.html"
    try:
        html_content = generate_report_html(report, auto_print=False)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"Saved HTML report to {html_path}")
    except Exception as e:
        logger.warning(f"Could not generate HTML report: {e}")

    # 3. Format GitHub Step Summary Markdown
    score_data = report.get("score_data", {})
    app_info = report.get("app_info", {})
    tech_info = report.get("tech_info", {})
    counts = score_data.get("counts", {})
    target_name = app_info.get("domain") or app_info.get("package") or target
    target_title = app_info.get("title") or target_name

    md_lines = [
        f"# 🛡️ Executive Security Audit Report: {target_title}",
        f"**Target:** `{target_name}` | **Type:** `{'🌐 Website' if is_web else '📱 Android APK'}` | **Version:** `{app_info.get('version_name', '1.0')}`",
        f"**Framework:** `{tech_info.get('primary_framework', 'Web / Native')}` | **Target SDK/Server:** `{app_info.get('target_sdk', 'N/A')}`",
        "",
        f"## 📊 Security Posture Score: **{score_data.get('score', 0)}/100** ({score_data.get('risk_level', 'AUDITED')})",
        "",
        "| Severity | Count | Impact Level |",
        "| :--- | :--- | :--- |",
        f"| 🔴 CRITICAL | **{counts.get('CRITICAL', 0)}** | Urgent Exploit / Credential Leak |",
        f"| 🟠 HIGH | **{counts.get('HIGH', 0)}** | Systemic Vulnerability |",
        f"| 🟡 MEDIUM | **{counts.get('MEDIUM', 0)}** | Security Hardening Needed |",
        f"| 🔵 LOW | **{counts.get('LOW', 0)}** | Minor Leakage / Header Flag |",
        f"| ⚪ INFO | **{counts.get('INFO', 0)}** | Informational / Observability |",
        "",
        "## 📋 Executive Briefing",
        report.get("executive_summary", "No executive summary available."),
        "",
        "## 🔥 Top Remediation Priorities"
    ]

    priorities = report.get("fix_these_first", [])
    if not priorities:
        md_lines.append("*No immediate critical security blockades found.*")
    else:
        for prio in priorities:
            md_lines.append(f"- **#{prio.get('priority')} [{prio.get('severity')}] {prio.get('title')}**")
            md_lines.append(f"  - *Impact:* {prio.get('potential_impact')}")
            md_lines.append(f"  - *Action Required:* {prio.get('action_required')}")

    md_content = "\n".join(md_lines)
    summary_path = "output_reports/summary.md"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as sf:
            sf.write(md_content)

    logger.info("GitHub Cloud Audit completed successfully.")

if __name__ == "__main__":
    main()
