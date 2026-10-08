import re
import logging
import requests
from typing import List, Dict, Any

logger = logging.getLogger("scanner.cloud_prober")

class CloudProber:
    """
    Performs passive, non-destructive safety checks against cloud endpoints
    discovered in APK strings (e.g. public Firebase databases, open Cloud Storage buckets, and readable S3 buckets).
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MobileSecurityAuditor/1.0"
    }

    def probe_text_for_cloud_resources(self, all_strings: str) -> List[Dict[str, Any]]:
        findings = []

        # 1. Firebase Realtime Database Prober
        firebase_urls = set(re.findall(r"https?://([a-zA-Z0-9\-]+)\.firebaseio\.com", all_strings, re.I))
        for proj_id in firebase_urls:
            base_fb = f"https://{proj_id}.firebaseio.com"
            probe_url = f"{base_fb}/.json?shallow=true"
            try:
                resp = requests.get(probe_url, headers=self.HEADERS, timeout=5)
                # If returns 200 and not "Permission denied" or "error"
                if resp.status_code == 200 and "error" not in resp.text.lower() and "permission_denied" not in resp.text.lower():
                    findings.append({
                        "id": "CLOUD-FB-001",
                        "category": "Cloud Configuration Exposure",
                        "title": f"Open Firebase Realtime Database ({proj_id})",
                        "severity": "CRITICAL",
                        "confidence": 0.99,
                        "exposure": "Publicly readable by unauthenticated internet users",
                        "evidence": {
                            "database_url": base_fb,
                            "probe_response_status": resp.status_code,
                            "probe_endpoint": probe_url
                        },
                        "impact": f"The Firebase database '{proj_id}' has insecure security rules (`.read: true`). Anyone with internet access can dump customer data or overwrite records.",
                        "remediation": "Update your Firebase Realtime Database rules in the Firebase Console to enforce authentication: `{ \"rules\": { \".read\": \"auth != null\", \".write\": \"auth != null\" } }`."
                    })
            except Exception as e:
                logger.debug(f"Firebase probe failed for {base_fb}: {e}")

        # 2. Firebase Cloud Storage Bucket Prober
        fb_storage_buckets = set()
        for pat in [r"([a-zA-Z0-9\.\-_]+)\.firebasestorage\.app", r"([a-zA-Z0-9\.\-_]+)\.appspot\.com"]:
            matches = re.findall(pat, all_strings, re.I)
            for b in matches:
                if b and len(b) > 3 and not b.startswith("com."):
                    fb_storage_buckets.add(b if "." in b else f"{b}.appspot.com")

        for bucket in list(fb_storage_buckets)[:5]:
            probe_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
            try:
                resp = requests.get(probe_url, headers=self.HEADERS, timeout=5)
                if resp.status_code == 200 and "items" in resp.text:
                    findings.append({
                        "id": "CLOUD-FB-002",
                        "category": "Cloud Storage Exposure",
                        "title": f"Publicly Readable Firebase Storage Bucket ({bucket})",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "exposure": "Anonymous public object listing enabled",
                        "evidence": {
                            "bucket": bucket,
                            "probe_url": probe_url,
                            "status": resp.status_code
                        },
                        "impact": f"The Firebase Cloud Storage bucket '{bucket}' permits anonymous listing and downloading of uploaded user media and files.",
                        "remediation": "Enforce Firebase Storage security rules requiring authentication: `allow read, write: if request.auth != null;`."
                    })
            except Exception as e:
                logger.debug(f"Firebase Storage probe failed for {bucket}: {e}")

        # 3. AWS S3 Public Bucket Prober
        s3_patterns = [
            r"https?://([a-zA-Z0-9\.\-_]+)\.s3[\.\-a-zA-Z0-9]*\.amazonaws\.com",
            r"https?://s3[\.\-a-zA-Z0-9]*\.amazonaws\.com/([a-zA-Z0-9\.\-_]+)"
        ]
        buckets = set()
        for pat in s3_patterns:
            matches = re.findall(pat, all_strings, re.I)
            for b in matches:
                if b and not b.startswith("com.") and len(b) > 3:
                    buckets.add(b)

        for bucket in list(buckets)[:5]:
            probe_url = f"https://{bucket}.s3.amazonaws.com/?max-keys=1"
            try:
                resp = requests.get(probe_url, headers=self.HEADERS, timeout=5)
                if resp.status_code == 200 and "<ListBucketResult" in resp.text:
                    findings.append({
                        "id": "CLOUD-S3-001",
                        "category": "Cloud Configuration Exposure",
                        "title": f"Publicly Readable AWS S3 Bucket ({bucket})",
                        "severity": "CRITICAL",
                        "confidence": 0.98,
                        "exposure": "Anonymous public bucket listing enabled",
                        "evidence": {
                            "bucket_name": bucket,
                            "probe_url": probe_url,
                            "status": resp.status_code
                        },
                        "impact": f"The S3 bucket '{bucket}' permits anonymous listing of all stored files, media, and database backups.",
                        "remediation": "Enable 'Block all public access' on the AWS S3 bucket and review Bucket Policies / IAM roles."
                    })
            except Exception as e:
                logger.debug(f"S3 probe failed for {bucket}: {e}")

        return findings
