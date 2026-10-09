import os
import re
import json
import logging
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("scanner.downloader")

class APKDownloader:
    """
    Downloads APK files from Play Store URLs, package names, or mirrors.
    Supports APKPure, APKCombo, and direct APK download endpoints without requiring Google credentials.
    """
    
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }

    @staticmethod
    def extract_package_name(url_or_package: str) -> str:
        """
        Extracts package name from Play Store URL or raw input.
        Examples:
        - https://play.google.com/store/apps/details?id=com.spotify.music -> com.spotify.music
        - market://details?id=com.spotify.music -> com.spotify.music
        - com.spotify.music -> com.spotify.music
        """
        cleaned = url_or_package.strip()
        if "play.google.com" in cleaned or "market://" in cleaned:
            parsed = urlparse(cleaned)
            query = parse_qs(parsed.query)
            if "id" in query and query["id"]:
                return query["id"][0]
        
        # Regex match for standard Android package identifier: com.example.app
        match = re.search(r'([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)', cleaned)
        if match:
            return match.group(1)
        
        return cleaned

    def fetch_app_details(self, package_name: str) -> Dict[str, Any]:
        """
        Fetches app title, developer, icon, and basic metadata from Google Play Store web page.
        """
        url = f"https://play.google.com/store/apps/details?id={package_name}&hl=en"
        details = {
            "package_name": package_name,
            "title": package_name,
            "developer": "Unknown",
            "icon_url": None,
            "version": "Unknown",
            "category": "Unknown",
            "rating": None
        }

        try:
            resp = requests.get(url, headers=self.HEADERS, timeout=10)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                
                # Title
                title_elem = soup.find("h1")
                if title_elem:
                    details["title"] = title_elem.text.strip()
                
                # App Icon
                icon_elem = soup.find("img", {"alt": "Cover art"}) or soup.find("img", {"alt": "Icon image"})
                if icon_elem and icon_elem.get("src"):
                    details["icon_url"] = icon_elem["src"]
                
                # Developer
                dev_elem = soup.find("div", string=re.compile(r"Contains ads|In-app purchases", re.I))
                for a in soup.find_all("a"):
                    if "/store/apps/developer" in a.get("href", "") or "/store/apps/dev" in a.get("href", ""):
                        details["developer"] = a.text.strip()
                        break
        except Exception as e:
            logger.warning(f"Could not fetch metadata from Play Store for {package_name}: {e}")

        return details

    def _resolve_aptoide_cdn(self, package_name: str) -> Optional[str]:
        """
        Queries Aptoide open catalog REST API for direct CDN APK download path.
        Fast, unblocked, and returns direct APK binary URL.
        """
        try:
            search_url = f"http://ws75.aptoide.com/api/7/apps/search/query={package_name}/limit=5"
            r = requests.get(search_url, headers=self.HEADERS, timeout=6)
            if r.status_code == 200:
                items = r.json().get("datalist", {}).get("list", [])
                for item in items:
                    if item.get("package") == package_name:
                        app_id = item.get("id")
                        if app_id:
                            r2 = requests.get(f"http://ws75.aptoide.com/api/7/app/get/app_id={app_id}", headers=self.HEADERS, timeout=6)
                            if r2.status_code == 200:
                                path = r2.json().get("nodes", {}).get("meta", {}).get("data", {}).get("file", {}).get("path")
                                if path and path.startswith("http"):
                                    return path
        except Exception as e:
            logger.debug(f"Aptoide resolver failed for {package_name}: {e}")
        return None

    CLOUDFLARE_RELAY_URL = os.environ.get("CLOUDFLARE_RELAY_URL", "https://apk-relay.su468581.workers.dev")

    def _relay_wrap(self, url: str) -> str:
        """Wraps a target URL through Cloudflare Global Edge Relay."""
        import urllib.parse
        if not self.CLOUDFLARE_RELAY_URL:
            return url
        return f"{self.CLOUDFLARE_RELAY_URL.rstrip('/')}/?url={urllib.parse.quote(url, safe='')}"

    def get_download_stream_url(self, package_name: str) -> Tuple[Optional[str], str]:
        """
        Resolves direct download URL for the package across multiple public mirrors.
        Returns: (download_url, source_name)
        """
        # Tier 1: Check Aptoide Direct CDN
        aptoide_url = self._resolve_aptoide_cdn(package_name)
        if aptoide_url:
            return aptoide_url, "Aptoide Direct CDN"

        # Tier 2: Cloudflare Edge Relay through APKPure
        apkpure_url = f"https://d.apkpure.net/b/APK/{package_name}?version=latest"
        relayed_apkpure = self._relay_wrap(apkpure_url)
        return relayed_apkpure, "Cloudflare Edge Relay (APKPure)"

    def download_apk(self, package_or_url: str, output_dir: str, progress_callback=None) -> Dict[str, Any]:
        """
        Orchestrates downloading an APK from a Play Store URL or package name.
        """
        package_name = self.extract_package_name(package_or_url)
        os.makedirs(output_dir, exist_ok=True)
        target_path = os.path.join(output_dir, f"{package_name}.apk")

        if progress_callback:
            progress_callback(f"Resolving package: {package_name}...", 10)

        app_meta = self.fetch_app_details(package_name)
        
        if progress_callback:
            progress_callback(f"Target: '{app_meta['title']}'. Querying APK mirrors...", 25)

        download_url, source = self.get_download_stream_url(package_name)

        if progress_callback:
            progress_callback(f"Downloading from {source}...", 40)

        resp = None
        # Try primary resolved mirror
        try:
            resp = requests.get(download_url, headers=self.HEADERS, stream=True, timeout=20, allow_redirects=True)
        except Exception as e:
            logger.warning(f"Primary mirror {source} failed: {e}. Cascading to fallback mirrors...")

        # If primary failed, try secondary mirrors via Cloudflare Relay
        if not resp or resp.status_code != 200:
            fallback_sources = [
                (self._relay_wrap(f"https://f-droid.org/repo/{package_name}.apk"), "Cloudflare (F-Droid)"),
                (self._relay_wrap(f"https://apkcombo.app/{package_name}/download/apk"), "Cloudflare (APKCombo)"),
                (f"https://f-droid.org/repo/{package_name}.apk", "F-Droid Direct"),
                (f"https://d.apkpure.net/b/APK/{package_name}?version=latest", "APKPure Direct")
            ]
            for fb_url, fb_name in fallback_sources:
                try:
                    r_fb = requests.get(fb_url, headers=self.HEADERS, stream=True, timeout=12, allow_redirects=True)
                    if r_fb.status_code == 200:
                        resp = r_fb
                        source = fb_name
                        break
                except Exception:
                    continue

        if not resp or resp.status_code != 200:
            raise RuntimeError(
                f"Could not automatically download APK for '{package_name}'. "
                f"Please download the APK file manually and run: `python run.py scan --target path/to/{package_name}.apk` or drop it into the web dashboard."
            )

        total_size = int(resp.headers.get('content-length', 0))
        downloaded = 0

        with open(target_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=1024 * 64):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0 and progress_callback:
                        percent = min(90, int(40 + (downloaded / total_size) * 50))
                        progress_callback(f"Downloading APK: {downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB", percent)

        file_size_mb = os.path.getsize(target_path) / (1024 * 1024)
        if file_size_mb < 0.1:
            raise RuntimeError(
                f"Downloaded file is incomplete ({file_size_mb:.2f} MB). "
                f"Please provide the .apk file directly: `python run.py scan --target path/to/app.apk`"
            )

        if progress_callback:
            progress_callback(f"Download complete ({file_size_mb:.2f} MB).", 95)

        return {
            "success": True,
            "package_name": package_name,
            "apk_path": target_path,
            "file_size_mb": round(file_size_mb, 2),
            "app_meta": app_meta,
            "source": source
        }

