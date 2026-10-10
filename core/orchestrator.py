import os
import uuid
import shutil
import logging
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from core.downloader import APKDownloader
from core.decompiler import DecompilerEngine
from core.tech_detector import TechnologyDetector
from core.manifest_analyzer import ManifestAnalyzer
from core.secret_classifier import SecretClassifier
from core.code_analyzer import CodeAnalyzer
from core.cloud_prober import CloudProber
from core.web_scanner import WebsiteScanner
from ai.gemini_engine import GeminiAuditor
from database.db import AuditDatabase

logger = logging.getLogger("scanner.orchestrator")

class AuditOrchestrator:
    """
    Coordinates the full end-to-end security audit pipeline:
    Download -> Decompile -> Tech Detect -> Manifest Audit -> Secret Classification ->
    Code Analysis -> Cloud Probing -> Gemini Executive Synthesis -> Database Storage.
    Also handles live Website Security Audits.
    """

    def __init__(self, workspace_dir: Optional[str] = None):
        if workspace_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.workspace_dir = os.path.join(base_dir, "workspace")
        else:
            self.workspace_dir = workspace_dir

        os.makedirs(self.workspace_dir, exist_ok=True)
        self.downloader = APKDownloader()
        self.decompiler = DecompilerEngine()
        self.tech_detector = TechnologyDetector()
        self.manifest_analyzer = ManifestAnalyzer()
        self.secret_classifier = SecretClassifier()
        self.code_analyzer = CodeAnalyzer()
        self.cloud_prober = CloudProber()
        self.web_scanner = WebsiteScanner()
        self.ai_auditor = GeminiAuditor()
        self.db = AuditDatabase()

    def run_audit(
        self,
        apk_path_or_url: str,
        is_url: bool = False,
        scan_id: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes a complete automated security audit on an APK.
        """
        scan_id = scan_id or f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        job_dir = os.path.join(self.workspace_dir, scan_id)
        os.makedirs(job_dir, exist_ok=True)

        def log_progress(msg: str, pct: int):
            logger.info(f"[{pct}%] {msg}")
            if progress_callback:
                progress_callback(msg, pct)

        try:
            log_progress("Initializing Security Audit Pipeline...", 5)
            
            # Step 1: Acquire APK
            app_meta = {}
            if is_url or "play.google.com" in apk_path_or_url or not os.path.exists(apk_path_or_url):
                log_progress(f"Acquiring APK for '{apk_path_or_url}'...", 10)
                download_res = self.downloader.download_apk(apk_path_or_url, job_dir, progress_callback=log_progress)
                apk_path = download_res["apk_path"]
                app_meta = download_res.get("app_meta", {})
            else:
                apk_path = apk_path_or_url
                app_meta = {
                    "package_name": os.path.splitext(os.path.basename(apk_path))[0],
                    "title": os.path.basename(apk_path),
                    "developer": "Local File Upload",
                    "icon_url": None
                }

            # Step 2: Unpack Container & Decompile
            log_progress("Unpacking APK container assets & native libraries...", 30)
            raw_unpack_dir = os.path.join(job_dir, "unpacked_raw")
            unpack_res = self.decompiler.unpack_raw_apk(apk_path, raw_unpack_dir)

            log_progress("Decompiling Dalvik/ART bytecode to Java with JADX...", 45)
            decompiled_dir = os.path.join(job_dir, "decompiled")
            decompile_res = self.decompiler.decompile_apk(apk_path, decompiled_dir, progress_callback=log_progress)

            if unpack_res["total_files"] == 0 and not decompile_res.get("has_sources"):
                raise RuntimeError(
                    f"APK archive appears empty or corrupted (0 classes/assets unpacked). "
                    f"Please provide a valid .apk or .xapk file."
                )

            # Step 3: Detect Technology Stack
            log_progress("Detecting framework, native architectures & cloud SDKs...", 60)
            tech_info = self.tech_detector.detect(raw_unpack_dir, unpack_res["files"])

            # Step 4: Audit AndroidManifest.xml
            log_progress("Auditing AndroidManifest.xml security configuration...", 70)
            manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                manifest_res = self.manifest_analyzer.analyze_from_file(manifest_path)
            else:
                manifest_res = self.manifest_analyzer.analyze_from_apk(apk_path)

            # Merge app info
            app_info = {
                "package": manifest_res.get("package") or app_meta.get("package_name") or "unknown",
                "title": app_meta.get("title") or manifest_res.get("package"),
                "developer": app_meta.get("developer", "Unknown"),
                "icon_url": app_meta.get("icon_url"),
                "version_name": manifest_res.get("version_name", "1.0"),
                "version_code": manifest_res.get("version_code", "1"),
                "min_sdk": manifest_res.get("min_sdk", "Unknown"),
                "target_sdk": manifest_res.get("target_sdk", "Unknown"),
                "file_size_mb": round(os.path.getsize(apk_path) / (1024 * 1024), 2)
            }

            # Step 5: Classify Secrets & Sensitive Tokens
            log_progress("Scanning decompiled code & configs for credentials and secret keys...", 80)
            target_scan_dir = decompiled_dir if decompile_res.get("has_sources") else raw_unpack_dir
            secret_findings = self.secret_classifier.scan_directory(target_scan_dir)

            # Step 6: Code-level Vulnerability Inspection
            log_progress("Auditing source code for TLS, WebViews, Crypto & Storage flaws...", 85)
            sources_dir = decompile_res.get("sources_dir")
            code_findings = self.code_analyzer.scan_directory(sources_dir) if sources_dir else []

            # Step 7: Passive Cloud Probing
            log_progress("Probing extracted cloud endpoints for open bucket/database permissions...", 90)
            all_findings_snippets = " ".join([f.get("evidence", {}).get("context_snippet", "") for f in secret_findings])
            # Also extract from manifest XML text if available
            manifest_text = manifest_res.get("raw_xml", "")
            cloud_search_text = f"{all_findings_snippets} {manifest_text}"
            cloud_findings, cloud_diagnostics = self.cloud_prober.probe_text_for_cloud_resources(cloud_search_text)

            # Aggregate all findings
            all_findings = []
            all_findings.extend(manifest_res.get("findings", []))
            all_findings.extend(secret_findings)
            all_findings.extend(code_findings)
            all_findings.extend(cloud_findings)

            # Step 8: Gemini Executive Synthesis
            log_progress("Generating executive security report and remediation matrix...", 95)
            executive_report = self.ai_auditor.generate_executive_report(app_info, tech_info, all_findings)

            # Assemble Final Audit Contract
            final_report = {
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "app_info": app_info,
                "tech_info": tech_info,
                "score_data": executive_report["score_data"],
                "executive_summary": executive_report["executive_summary"],
                "fix_these_first": executive_report["fix_these_first"],
                "architectural_recommendations": executive_report["architectural_recommendations"],
                "ai_engine": executive_report.get("generated_by", "Gemini 2.5 Flash"),
                "manifest_summary": {
                    "permissions_count": len(manifest_res.get("permissions", [])),
                    "exported_components_count": manifest_res.get("exported_components_count", 0),
                    "unguarded_exported_count": manifest_res.get("unguarded_exported_count", 0),
                    "deep_links_count": manifest_res.get("deep_links_count", 0)
                },
                "cloud_diagnostics": cloud_diagnostics,
                "findings": all_findings
            }

            # Step 9: Save to SQLite Database
            self.db.save_scan(final_report)

            log_progress(f"Audit completed! Security Score: {final_report['score_data']['score']}/100", 100)
            return final_report

        except Exception as e:
            logger.error(f"Audit failed with error: {traceback.format_exc()}")
            raise
        finally:
            # Clean up temp workspace files if needed, keep scan artifacts
            pass

    def run_web_audit(
        self,
        target_url: str,
        scan_id: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes a complete automated security audit on a website / web application.
        """
        scan_id = scan_id or f"SCAN-WEB-{uuid.uuid4().hex[:6].upper()}"

        def log_progress(msg: str, pct: int):
            logger.info(f"[{pct}%] {msg}")
            if progress_callback:
                progress_callback(msg, pct)

        try:
            log_progress(f"Initializing Web Security Audit Pipeline for '{target_url}'...", 5)
            web_res = self.web_scanner.audit_website(target_url, progress_callback=log_progress)

            app_info = web_res["app_info"]
            tech_info = web_res["tech_info"]
            findings = web_res["findings"]
            cloud_diagnostics = web_res.get("cloud_diagnostics", [])

            log_progress("Synthesizing executive security briefing and remediation matrix with AI...", 95)
            executive_report = self.ai_auditor.generate_executive_report(app_info, tech_info, findings)

            final_report = {
                "scan_id": scan_id,
                "timestamp": datetime.utcnow().isoformat(),
                "app_info": app_info,
                "tech_info": tech_info,
                "score_data": executive_report["score_data"],
                "executive_summary": executive_report["executive_summary"],
                "fix_these_first": executive_report["fix_these_first"],
                "architectural_recommendations": executive_report["architectural_recommendations"],
                "ai_engine": executive_report.get("generated_by", "Gemini 2.5 Flash"),
                "manifest_summary": {
                    "permissions_count": 0,
                    "exported_components_count": 0,
                    "unguarded_exported_count": 0,
                    "deep_links_count": 0
                },
                "cloud_diagnostics": cloud_diagnostics,
                "findings": findings
            }

            self.db.save_scan(final_report)
            log_progress(f"Web Audit completed! Security Score: {final_report['score_data']['score']}/100", 100)
            return final_report
        except Exception as e:
            logger.error(f"Web audit failed with error: {traceback.format_exc()}")
            raise

