import os
import io
import time
import json
import zipfile
import logging
import requests
from typing import Dict, Any, Optional, Callable, List

logger = logging.getLogger("scanner.github_runner")

class GitHubActionsRunner:
    """
    Triggers, streams, and retrieves security audit runs directly on GitHub Actions cloud runners
    via the GitHub REST API without requiring local machine CPU/RAM.
    """

    def __init__(self, owner: str = "shivamupadhyay6501-lang", repo: str = "dec", token: Optional[str] = None):
        self.owner = owner
        self.repo = repo
        self.token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.workflow_id = "apk_audit.yml"

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Decryptor-Security-Intelligence-Bot/1.0"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    def get_latest_run_id(self) -> Optional[int]:
        """Gets the run ID of the latest workflow run currently registered on GitHub for apk_audit.yml."""
        try:
            url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/{self.workflow_id}/runs?per_page=1"
            resp = requests.get(url, headers=self._get_headers(), timeout=8)
            if resp.status_code == 200:
                runs = resp.json().get("workflow_runs", [])
                if runs:
                    return runs[0]["id"]
                return 0
        except Exception as e:
            logger.debug(f"Could not get current latest run ID: {e}")
        return None

    def trigger_workflow(self, target: str, target_type: Optional[str] = None, scan_id: Optional[str] = None, gemini_api_key: Optional[str] = None, ref: str = "main") -> Dict[str, Any]:
        """
        Dispatches a workflow run on GitHub Actions after recording the current latest run ID.
        """
        if not self.token:
            raise ValueError("GitHub Personal Access Token (GITHUB_TOKEN) is required. Please configure it in Settings tab.")

        from core.target_classifier import classify_target
        normalized_target, is_web = classify_target(target, explicit_type=target_type)
        resolved_type = target_type or ("web" if is_web else "apk")

        # Snapshot the latest run ID before dispatch so we NEVER mistake a previous run for this one
        prev_run_id = self.get_latest_run_id()

        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/{self.workflow_id}/dispatches"
        payload = {
            "ref": ref,
            "inputs": {
                "target": normalized_target,
                "target_type": resolved_type,
                "scan_id": scan_id or "",
                "gemini_api_key": gemini_api_key or ""
            }
        }

        dispatch_time = time.time()
        resp = requests.post(url, json=payload, headers=self._get_headers(), timeout=15)
        
        if resp.status_code in (204, 201, 200):
            return {
                "success": True,
                "dispatched_at": dispatch_time,
                "prev_run_id": prev_run_id,
                "target": normalized_target,
                "target_type": resolved_type,
                "scan_id": scan_id,
                "owner": self.owner,
                "repo": self.repo
            }
        else:
            err_msg = resp.text
            logger.error(f"GitHub API Error: {resp.status_code} - {err_msg}")
            raise RuntimeError(f"GitHub API Error ({resp.status_code}): {err_msg}")

    def find_latest_run(self, dispatched_after: float, prev_run_id: Optional[int] = None, max_wait_sec: int = 90, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict[str, Any]:
        """
        Polls GitHub API until the NEW workflow run (created after dispatch) appears in GitHub's queue.
        Strictly guarantees that old completed runs from previous audits are NEVER returned.
        """
        from datetime import datetime
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/{self.workflow_id}/runs?per_page=5"
        start_wait = time.time()

        while (time.time() - start_wait) < max_wait_sec:
            elapsed = int(time.time() - start_wait)
            try:
                resp = requests.get(url, headers=self._get_headers(), timeout=10)
                if resp.status_code == 200:
                    runs = resp.json().get("workflow_runs", [])
                    for run in runs:
                        run_id = run["id"]
                        
                        # Rule 1: If prev_run_id is known, new run must have id > prev_run_id
                        if prev_run_id is not None:
                            if run_id > prev_run_id:
                                logger.info(f"Matched new GitHub Actions run #{run_id} (status: {run.get('status')})")
                                return run
                            else:
                                continue # strictly skip all runs <= prev_run_id

                        # Rule 2: If prev_run_id was not captured, check status and timestamp
                        if run.get("status") in ("queued", "in_progress"):
                            logger.info(f"Matched in-progress GitHub Actions run #{run_id}")
                            return run

                        created_at_str = run.get("created_at", "")
                        try:
                            created_dt = datetime.fromisoformat(created_at_str.replace("Z", "+00:00")).timestamp()
                            if created_dt >= (dispatched_after - 10):
                                logger.info(f"Matched new GitHub Actions run #{run_id} (status: {run.get('status')})")
                                return run
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"Waiting for run registration: {e}")

            if progress_callback:
                progress_callback(f"[CLOUD] Waiting for GitHub to assign new runner ({elapsed}s elapsed)...", 10)
            time.sleep(3)

        raise TimeoutError("Timed out waiting for GitHub Actions workflow to register in repository.")

    def stream_run_execution(self, run_id: int, progress_callback: Optional[Callable[[str, int], None]] = None, timeout_sec: int = 600) -> Dict[str, Any]:
        """
        Monitors a running GitHub Actions workflow until completion, streaming exact real-time steps and jobs.
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{run_id}"
        jobs_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/jobs"
        start_time = time.time()
        last_step_reported = ""
        last_heartbeat_time = 0
        pct = 15

        while (time.time() - start_time) < timeout_sec:
            elapsed = int(time.time() - start_time)
            try:
                resp = requests.get(url, headers=self._get_headers(), timeout=10)
                if resp.status_code == 200:
                    run_info = resp.json()
                    status = run_info.get("status") # queued, in_progress, completed
                    conclusion = run_info.get("conclusion") # success, failure, cancelled, etc.
                    html_url = run_info.get("html_url")

                    if status == "completed":
                        if conclusion == "success":
                            if progress_callback:
                                progress_callback(f"[CLOUD] GitHub Actions workflow completed successfully! ({elapsed}s total). Downloading artifacts...", 90)
                            return run_info
                        else:
                            raise RuntimeError(f"GitHub Actions workflow finished with status '{conclusion}'. See run logs: {html_url}")

                    # Query jobs API to get the EXACT step currently running on GitHub Actions!
                    step_name = None
                    try:
                        jobs_resp = requests.get(jobs_url, headers=self._get_headers(), timeout=8)
                        if jobs_resp.status_code == 200:
                            jobs_data = jobs_resp.json().get("jobs", [])
                            if jobs_data:
                                job = jobs_data[0]
                                steps = job.get("steps", [])
                                for s in steps:
                                    if s.get("status") == "in_progress":
                                        step_name = s.get("name")
                                        break
                                if not step_name and steps:
                                    completed = [s for s in steps if s.get("status") == "completed"]
                                    if completed:
                                        step_name = completed[-1].get("name")
                    except Exception as e:
                        logger.debug(f"Could not poll jobs steps: {e}")

                    # Step to progress percentage mapping
                    step_pct_map = {
                        "Checkout Codebase": 18,
                        "Set up Java 17 (for JADX Decompiler)": 25,
                        "Set up Python 3.11": 35,
                        "Install Dependencies": 45,
                        "Execute Security Audit Pipeline": 65,
                        "Upload Security Reports as Artifacts": 88
                    }

                    if step_name:
                        current_pct = step_pct_map.get(step_name, pct)
                        if step_name == "Execute Security Audit Pipeline":
                            # Dynamic progression between 55% and 85%
                            extra = min(25, int((elapsed % 40) * 0.7))
                            current_pct = max(current_pct, 55 + extra)

                        if step_name != last_step_reported:
                            last_step_reported = step_name
                            last_heartbeat_time = elapsed
                            if progress_callback:
                                progress_callback(f"[CLOUD] Step: {step_name} ({elapsed}s elapsed)...", current_pct)
                        elif elapsed - last_heartbeat_time >= 6:
                            # Periodic heartbeat for long-running steps like audit pipeline
                            last_heartbeat_time = elapsed
                            if progress_callback:
                                progress_callback(f"[CLOUD] Executing: {step_name} ({elapsed}s elapsed)...", current_pct)
                    else:
                        if status == "queued":
                            if progress_callback: progress_callback(f"[CLOUD] Queued in GitHub cloud runner pool ({elapsed}s)...", 15)
                        elif status == "in_progress":
                            if pct < 85: pct += 2
                            if progress_callback: progress_callback(f"[CLOUD] Runner executing security audit ({elapsed}s)...", pct)

            except Exception as e:
                logger.debug(f"Error polling run status: {e}")
                if "workflow finished with status" in str(e):
                    raise

            time.sleep(3)

        raise TimeoutError(f"GitHub Actions run exceeded timeout limit of {timeout_sec}s.")

    def download_report_artifact(self, run_id: int) -> Dict[str, Any]:
        """
        Downloads the artifact ZIP from the completed GitHub Actions run and extracts report.json.
        """
        artifacts_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/artifacts"
        resp = requests.get(artifacts_url, headers=self._get_headers(), timeout=15)
        
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch artifacts for run {run_id}: HTTP {resp.status_code}")

        artifacts = resp.json().get("artifacts", [])
        if not artifacts:
            raise RuntimeError(f"No artifact uploaded in GitHub Actions run {run_id}. Check if the workflow completed.")

        target_artifact = artifacts[0]
        download_url = target_artifact.get("archive_download_url")

        # Step 1: Request GitHub artifact endpoint with auth, but do NOT follow redirect automatically
        # to prevent sending the GitHub Authorization header to Azure/AWS S3 storage (which causes 403 Signature error)
        dl_init_resp = requests.get(download_url, headers=self._get_headers(), allow_redirects=False, timeout=20)
        
        if dl_init_resp.status_code in (301, 302, 307, 308) and "Location" in dl_init_resp.headers:
            storage_url = dl_init_resp.headers["Location"]
            # Step 2: Download artifact directly from Azure/S3 pre-signed URL without GitHub Authorization header
            dl_resp = requests.get(storage_url, timeout=60)
        elif dl_init_resp.status_code == 200:
            dl_resp = dl_init_resp
        else:
            raise RuntimeError(f"Failed to get artifact download URL: HTTP {dl_init_resp.status_code} - {dl_init_resp.text}")

        if dl_resp.status_code != 200:
            raise RuntimeError(f"Failed to download artifact archive: HTTP {dl_resp.status_code}")

        zip_bytes = dl_resp.content
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            if "report.json" in z.namelist():
                report_content = z.read("report.json").decode("utf-8")
                return json.loads(report_content)
            else:
                raise RuntimeError("report.json not found inside downloaded artifact zip.")

    def sync_recent_cloud_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Fetches all recent completed workflow runs from GitHub and extracts their reports.
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs?event=workflow_dispatch&per_page={limit}"
        resp = requests.get(url, headers=self._get_headers(), timeout=15)
        if resp.status_code != 200:
            logger.error(f"Failed to list GitHub workflow runs: HTTP {resp.status_code}")
            return []

        runs = resp.json().get("workflow_runs", [])
        synced_reports = []
        for run in runs:
            if run.get("status") == "completed" and run.get("conclusion") == "success":
                run_id = run["id"]
                try:
                    report = self.download_report_artifact(run_id)
                    report["cloud_run_url"] = run.get("html_url")
                    report["cloud_executor"] = "GitHub Actions (Ubuntu Linux)"
                    synced_reports.append(report)
                except Exception as e:
                    logger.debug(f"Could not download artifact for run {run_id}: {e}")

        return synced_reports

    def execute_cloud_audit(self, target: str, target_type: Optional[str] = None, scan_id: Optional[str] = None, gemini_api_key: Optional[str] = None, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict[str, Any]:
        """
        Complete end-to-end cloud audit on GitHub Actions:
        Dispatch -> Wait for NEW Runner -> Stream Execution -> Download Exact Report Artifact.
        """
        if progress_callback:
            progress_callback(f"[CLOUD] Dispatching security audit on GitHub Actions ({self.owner}/{self.repo})...", 5)

        dispatch_res = self.trigger_workflow(target, target_type=target_type, scan_id=scan_id, gemini_api_key=gemini_api_key)
        
        if progress_callback:
            progress_callback("[CLOUD] Workflow dispatched! Waiting for new runner assignment...", 10)

        run_info = self.find_latest_run(
            dispatched_after=dispatch_res["dispatched_at"],
            prev_run_id=dispatch_res.get("prev_run_id"),
            progress_callback=progress_callback
        )
        run_id = run_info["id"]

        if progress_callback:
            progress_callback(f"[CLOUD] Runner assigned (Run #{run_id}). Streaming execution...", 20)

        completed_run = self.stream_run_execution(run_id, progress_callback=progress_callback)
        
        if progress_callback:
            progress_callback("[CLOUD] Downloading report artifact from GitHub...", 90)

        report = self.download_report_artifact(run_id)
        
        if scan_id:
            report["scan_id"] = scan_id

        report["cloud_run_url"] = completed_run.get("html_url")
        report["cloud_executor"] = "GitHub Actions (Ubuntu Linux)"

        if progress_callback:
            progress_callback(f"[CLOUD] Audit Complete! Score: {report.get('score_data', {}).get('score', 0)}/100", 100)

        return report
