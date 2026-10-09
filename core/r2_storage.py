import os
import json
import logging
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("scanner.r2_storage")

class CloudflareR2Storage:
    """
    Cloudflare R2 Object Storage Manager for security audits, reports, and database snapshots.
    Supports:
    1. Direct Cloudflare Edge Worker Storage Relay (Zero-config edge streaming)
    2. Direct S3/R2 REST API endpoint (SigV4)
    3. Auto-syncing of scan reports and audit history across ephemeral server restarts
    """

    DEFAULT_WORKER_URL = "https://apk-relay.su468581.workers.dev"
    DEFAULT_BUCKET = "mobile-audits"

    def __init__(
        self,
        worker_url: Optional[str] = None,
        account_id: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        bucket_name: Optional[str] = None
    ):
        self.worker_url = (worker_url or os.environ.get("CLOUDFLARE_RELAY_URL") or self.DEFAULT_WORKER_URL).rstrip("/")
        self.account_id = account_id or os.environ.get("R2_ACCOUNT_ID") or os.environ.get("CLOUDFLARE_ACCOUNT_ID", "09f855ac9a499b9d0b63529456987ffa")
        self.access_key_id = access_key_id or os.environ.get("R2_ACCESS_KEY_ID") or os.environ.get("CLOUDFLARE_R2_ACCESS_KEY_ID")
        self.secret_access_key = secret_access_key or os.environ.get("R2_SECRET_ACCESS_KEY") or os.environ.get("CLOUDFLARE_R2_SECRET_ACCESS_KEY")
        self.bucket_name = bucket_name or os.environ.get("R2_BUCKET_NAME", self.DEFAULT_BUCKET)
        
        self.s3_endpoint = f"https://{self.account_id}.r2.cloudflarestorage.com/{self.bucket_name}"

    def is_configured(self) -> bool:
        """Returns True if either Worker Edge Storage or direct R2 credentials are active."""
        return bool(self.worker_url or (self.access_key_id and self.secret_access_key))

    def upload_scan(self, scan_data: Dict[str, Any]) -> bool:
        """
        Uploads a completed audit report JSON to Cloudflare R2 bucket.
        Path: scans/{scan_id}.json
        """
        scan_id = scan_data.get("scan_id")
        if not scan_id:
            return False

        key = f"scans/{scan_id}.json"
        payload = json.dumps(scan_data, ensure_ascii=False)

        try:
            # 1. Try Cloudflare Worker Relay
            url = f"{self.worker_url}/storage/{key}"
            headers = {"Content-Type": "application/json", "X-R2-Bucket": self.bucket_name}
            resp = requests.put(url, data=payload.encode("utf-8"), headers=headers, timeout=12)
            if resp.status_code in (200, 201, 204):
                logger.info(f"Successfully uploaded scan {scan_id} to Cloudflare R2 via Edge Worker.")
                self._update_index_manifest(scan_data)
                return True
            else:
                logger.debug(f"Worker R2 upload returned status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.debug(f"Worker R2 upload failed for {scan_id}: {e}")

        # 2. Try direct S3 if boto3 or direct credentials exist
        if self.access_key_id and self.secret_access_key:
            try:
                import boto3
                s3 = boto3.client(
                    "s3",
                    endpoint_url=f"https://{self.account_id}.r2.cloudflarestorage.com",
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key
                )
                s3.put_object(
                    Bucket=self.bucket_name,
                    Key=key,
                    Body=payload.encode("utf-8"),
                    ContentType="application/json"
                )
                logger.info(f"Successfully uploaded scan {scan_id} to Cloudflare R2 via S3 API.")
                return True
            except Exception as e:
                logger.debug(f"Direct S3 R2 upload failed: {e}")

        return False

    def _update_index_manifest(self, scan_data: Dict[str, Any]):
        """Updates the top-level scans index manifest in R2 for rapid history synchronization."""
        try:
            summary = {
                "id": scan_data.get("scan_id"),
                "account_id": scan_data.get("account_id"),
                "package_name": scan_data.get("app_info", {}).get("package"),
                "app_title": scan_data.get("app_info", {}).get("title"),
                "version_name": scan_data.get("app_info", {}).get("version_name", "1.0"),
                "version_code": str(scan_data.get("app_info", {}).get("version_code", "1")),
                "framework": scan_data.get("tech_info", {}).get("primary_framework", "Native Android"),
                "security_score": scan_data.get("score_data", {}).get("score", 0),
                "risk_level": scan_data.get("score_data", {}).get("risk_level", "UNKNOWN"),
                "critical_count": scan_data.get("score_data", {}).get("counts", {}).get("CRITICAL", 0),
                "high_count": scan_data.get("score_data", {}).get("counts", {}).get("HIGH", 0),
                "medium_count": scan_data.get("score_data", {}).get("counts", {}).get("MEDIUM", 0),
                "low_count": scan_data.get("score_data", {}).get("counts", {}).get("LOW", 0),
                "info_count": scan_data.get("score_data", {}).get("counts", {}).get("INFO", 0),
                "total_findings": len(scan_data.get("findings", [])),
                "created_at": scan_data.get("timestamp") or datetime.utcnow().isoformat()
            }
            url = f"{self.worker_url}/storage/index/{scan_data.get('scan_id')}.json"
            requests.put(url, json=summary, timeout=8)
        except Exception as e:
            logger.debug(f"Could not update index manifest: {e}")

    def fetch_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Downloads a specific scan report from Cloudflare R2."""
        key = f"scans/{scan_id}.json"
        try:
            url = f"{self.worker_url}/storage/{key}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.debug(f"Failed to fetch scan {scan_id} from R2: {e}")
        return None

    def list_remote_scans(self) -> List[Dict[str, Any]]:
        """Queries Cloudflare R2 for all indexed scans."""
        try:
            url = f"{self.worker_url}/storage/index"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "items" in data:
                    return data["items"]
        except Exception as e:
            logger.debug(f"Failed to list scans from R2: {e}")
        return []

    def sync_all_to_database(self, db) -> Dict[str, Any]:
        """
        Synchronizes all remote scans stored in Cloudflare R2 into the local SQLite database.
        Ensures audit history is 100% persistent across server restarts, Render redeploys, and GitHub Actions.
        """
        remote_items = self.list_remote_scans()
        synced_count = 0
        
        for item in remote_items:
            scan_id = item.get("id") or item.get("scan_id")
            if not scan_id:
                continue
            
            # Check if scan already exists in local SQLite
            existing = db.get_scan(scan_id)
            if not existing:
                full_scan = self.fetch_scan(scan_id)
                if full_scan:
                    db.save_scan(full_scan, account_id=full_scan.get("account_id"))
                    synced_count += 1

        # Also push any local scans that are missing in R2
        local_scans = db.list_scans(limit=50)
        pushed_count = 0
        for l in local_scans:
            sid = l.get("id")
            # If not in remote, upload
            if not any(r.get("id") == sid or r.get("scan_id") == sid for r in remote_items):
                full_local = db.get_scan(sid)
                if full_local:
                    if self.upload_scan(full_local):
                        pushed_count += 1

        return {
            "status": "success",
            "remote_total": len(remote_items),
            "synced_to_local": synced_count,
            "pushed_to_remote": pushed_count
        }
