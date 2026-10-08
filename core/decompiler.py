import os
import sys
import zipfile
import subprocess
import shutil
import logging
import requests
import platform
from typing import Optional, Dict, Any

logger = logging.getLogger("scanner.decompiler")

JADX_VERSION = "1.5.0"
JADX_DOWNLOAD_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"

class DecompilerEngine:
    """
    Manages JADX installation and decompiler execution.
    Handles raw APK unzipping, DEX decompilation, asset extraction, and resource decoding.
    """

    def __init__(self, tools_dir: Optional[str] = None):
        if tools_dir is None:
            # Default to tools/ directory inside project root
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.tools_dir = os.path.join(base_dir, "tools")
        else:
            self.tools_dir = tools_dir
        
        self.jadx_bin = self._resolve_jadx_binary()

    def _resolve_jadx_binary(self) -> Optional[str]:
        """Locates jadx in system PATH or local tools/ folder."""
        # 1. Check local tools directory
        ext = ".bat" if platform.system() == "Windows" else ""
        local_jadx = os.path.join(self.tools_dir, "jadx", "bin", f"jadx{ext}")
        if os.path.exists(local_jadx):
            return local_jadx

        # 2. Check system PATH
        jadx_in_path = shutil.which(f"jadx{ext}") or shutil.which("jadx")
        if jadx_in_path:
            return jadx_in_path

        return None

    def ensure_jadx_installed(self, progress_callback=None) -> str:
        """
        Ensures JADX is installed. If not found, downloads and extracts the official release zip.
        """
        if self.jadx_bin and os.path.exists(self.jadx_bin):
            return self.jadx_bin

        os.makedirs(self.tools_dir, exist_ok=True)
        jadx_dest = os.path.join(self.tools_dir, "jadx")
        zip_path = os.path.join(self.tools_dir, f"jadx-{JADX_VERSION}.zip")

        if progress_callback:
            progress_callback(f"JADX not found. Downloading JADX v{JADX_VERSION} release (~40MB)...", 5)

        logger.info(f"Downloading JADX from {JADX_DOWNLOAD_URL}...")
        resp = requests.get(JADX_DOWNLOAD_URL, stream=True, timeout=60)
        resp.raise_for_status()

        total_size = int(resp.headers.get('content-length', 0))
        downloaded = 0

        with open(zip_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=1024 * 128):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0 and progress_callback:
                        pct = int(5 + (downloaded / total_size) * 20)
                        progress_callback(f"Downloading JADX: {downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB", pct)

        if progress_callback:
            progress_callback("Extracting JADX binaries...", 28)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(jadx_dest)

        if os.path.exists(zip_path):
            os.remove(zip_path)

        ext = ".bat" if platform.system() == "Windows" else ""
        jadx_executable = os.path.join(jadx_dest, "bin", f"jadx{ext}")

        if platform.system() != "Windows":
            os.chmod(jadx_executable, 0o755)

        self.jadx_bin = jadx_executable
        logger.info(f"JADX ready at {self.jadx_bin}")
        return self.jadx_bin

    def unpack_raw_apk(self, apk_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Fast unzipping of the APK container.
        Extracts assets, resources, native libraries (.so), and DEX files.
        """
        os.makedirs(output_dir, exist_ok=True)
        unpacked_files = []

        with zipfile.ZipFile(apk_path, 'r') as zf:
            for member in zf.infolist():
                # Prevent Zip Slip vulnerability
                target_path = os.path.abspath(os.path.join(output_dir, member.filename))
                if not target_path.startswith(os.path.abspath(output_dir)):
                    continue
                zf.extract(member, output_dir)
                unpacked_files.append(member.filename)

        return {
            "unpacked_dir": output_dir,
            "total_files": len(unpacked_files),
            "files": unpacked_files
        }

    def decompile_apk(self, apk_path: str, output_dir: str, progress_callback=None) -> Dict[str, Any]:
        """
        Runs JADX CLI to decompile the APK to Java source code and decode resources/manifest.
        """
        jadx_path = self.ensure_jadx_installed(progress_callback)
        os.makedirs(output_dir, exist_ok=True)

        if progress_callback:
            progress_callback("Decompiling APK bytecode with JADX (multi-threaded)...", 35)

        cmd = [
            jadx_path,
            "-d", output_dir,           # Output directory
            "--no-debug-info",          # Faster decompilation
            "--threads-count", "4",     # 4 threads
            "--show-bad-code",          # Keep going even on bad bytecodes
            apk_path
        ]

        logger.info(f"Executing JADX: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180  # 3 minutes max
            )
            logger.info(f"JADX exited with code {result.returncode}")
        except subprocess.TimeoutExpired:
            logger.warning("JADX timed out after 180s. Partial decompilation available.")
        except Exception as e:
            logger.error(f"JADX decompilation failed: {e}")
            raise

        sources_dir = os.path.join(output_dir, "sources")
        resources_dir = os.path.join(output_dir, "resources")

        has_sources = os.path.exists(sources_dir) and len(os.listdir(sources_dir)) > 0
        has_resources = os.path.exists(resources_dir)

        if progress_callback:
            progress_callback("Decompilation complete. Indexing source tree...", 50)

        return {
            "output_dir": output_dir,
            "sources_dir": sources_dir if has_sources else None,
            "resources_dir": resources_dir if has_resources else None,
            "has_sources": has_sources
        }
