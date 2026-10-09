import os
import io
import time
import json
import zipfile
import logging
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional, Callable, Tuple

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

    def trigger_workflow(self, target: str, gemini_api_key: Optional[str] = None, ref: str = "main") -> Dict[str, Any]:
        """
        Dispatches a workflow run on GitHub Actions.
        """
        if not self.token:
            raise ValueError("GitHub Personal Access Token (GITHUB_TOKEN) is required to trigger GitHub Actions via API. Please configure it in Settings or .env.")

        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/workflows/{self.workflow_id}/dispatches"
        payload = {
            "ref": ref,
            "inputs": {
                "target": target.strip(),
                "gemini_api_key": gemini_api_key or ""
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=self._get_headers(), method="POST")

        dispatch_time = time.time()
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status in (204, 201, 200):
                    return {
                        "success": True,
                        "dispatched_at": dispatch_time,
                        "target": target,
                        "owner": self.owner,
                        "repo": self.repo
                    }
                else:
                    raise RuntimeError(f"Unexpected status code {resp.status} from GitHub API")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.error(f"GitHub API Error: {e.code} - {err_body}")
            raise RuntimeError(f"GitHub API Error ({e.code}): {err_body}")

    def find_latest_run(self, dispatched_after: float, max_wait_sec: int = 45, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict[str, Any]:
        """
        Polls GitHub API to find the workflow run triggered after dispatch time.
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs?event=workflow_dispatch&per_page=5"
        start_wait = time.time()

        while (time.time() - start_wait) < max_wait_sec:
            req = urllib.request.Request(url, headers=self._get_headers())
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    runs = data.get("workflow_runs", [])
                    if runs:
                        latest_run = runs[0]
                        # Check run creation time or ID
                        return latest_run
            except Exception as e:
                logger.debug(f"Waiting for run registration: {e}")

            if progress_callback:
                progress_callback("Waiting for GitHub Actions cloud runner assignment...", 15)
            time.sleep(3)

        raise TimeoutError("Timed out waiting for GitHub Actions workflow to register in repository.")

    def stream_run_execution(self, run_id: int, progress_callback: Optional[Callable[[str, int], None]] = None, timeout_sec: int = 600) -> Dict[str, Any]:
        """
        Monitors a running GitHub Actions workflow until completion.
        """
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{run_id}"
        start_time = time.time()
        last_status = ""

        pct = 20
        while (time.time() - start_time) < timeout_sec:
            req = urllib.request.Request(url, headers=self._get_headers())
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    run_info = json.loads(resp.read().decode("utf-8"))
                    status = run_info.get("status") # queued, in_progress, completed
                    conclusion = run_info.get("conclusion") # success, failure, cancelled, etc.
                    html_url = run_info.get("html_url")

                    if status != last_status:
                        last_status = status
                        if status == "queued":
                            if progress_callback: progress_callback(f"[CLOUD] Queued in GitHub cloud runner pool ({html_url})...", 20)
                        elif status == "in_progress":
                            if progress_callback: progress_callback(f"[CLOUD] Runner active (Ubuntu Linux). Executing JADX bytecode & security audit...", 50)

                    if status == "completed":
                        if conclusion == "success":
                            if progress_callback: progress_callback("[CLOUD] GitHub Actions audit succeeded! Downloading report artifacts...", 90)
                            return run_info
                        else:
                            raise RuntimeError(f"GitHub Actions workflow finished with status '{conclusion}'. See run logs: {html_url}")

                    # Incremental progress ticker
                    if pct < 85:
                        pct += 2
                    if progress_callback:
                        progress_callback(f"[CLOUD] Processing on GitHub Actions ({int(time.time() - start_time)}s elapsed)...", pct)

            except Exception as e:
                logger.debug(f"Error polling run status: {e}")

            time.sleep(5)

        raise TimeoutError(f"GitHub Actions run exceeded timeout limit of {timeout_sec}s.")

    def download_report_artifact(self, run_id: int) -> Dict[str, Any]:
        """
        Downloads the artifact ZIP from the completed GitHub Actions run and extracts report.json.
        """
        artifacts_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/artifacts"
        req = urllib.request.Request(artifacts_url, headers=self._get_headers())

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            artifacts = data.get("artifacts", [])
            if not artifacts:
                raise RuntimeError(f"No artifact uploaded in GitHub Actions run {run_id}.")

            target_artifact = artifacts[0]
            download_url = target_artifact.get("archive_download_url")

        # Download artifact zip
        dl_req = urllib.request.Request(download_url, headers=self._get_headers())
        with urllib.request.urlopen(dl_req, timeout=30) as dl_resp:
            zip_bytes = dl_resp.read()

        # Extract report.json from in-memory zip
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            if "report.json" in z.namelist():
                report_content = z.read("report.json").decode("utf-8")
                return json.loads(report_content)
            else:
                raise RuntimeError("report.json not found inside downloaded artifact zip.")

    def execute_cloud_audit(self, target: str, gemini_api_key: Optional[str] = None, progress_callback: Optional[Callable[[str, int], None]] = None) -> Dict[str, Any]:
        """
        Complete end-to-end cloud audit on GitHub Actions:
        Dispatch -> Wait for Runner -> Stream Execution -> Download Artifact Report.
        """
        if progress_callback:
            progress_callback(f"[CLOUD] Dispatching security audit on GitHub Actions ({self.owner}/{self.repo})...", 5)

        dispatch_res = self.trigger_workflow(target, gemini_api_key=gemini_api_key)
        run_info = self.find_latest_run(dispatch_res["dispatched_at"], progress_callback=progress_callback)
        run_id = run_info["id"]

        completed_run = self.stream_run_execution(run_id, progress_callback=progress_callback)
        report = self.download_report_artifact(run_id)
        
        # Tag report with cloud executor metadata
        report["cloud_run_url"] = completed_run.get("html_url")
        report["cloud_executor"] = "GitHub Actions (Ubuntu Linux)"

        if progress_callback:
            progress_callback(f"[CLOUD] Audit Complete! Score: {report.get('score_data', {}).get('score', 0)}/100", 100)

        return report
