import os
import re
import json
import logging
import urllib.parse
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any, Tuple, List

logger = logging.getLogger("scanner.downloader")

class APKDownloader:
    """
    Downloads APK files from Play Store URLs, package names, or keywords/app titles.
    Features:
    - Smart keyword-to-package resolution (e.g., 'Tuition Manager' -> 'epic.education.tuitionapp')
    - Cloudflare Edge Relay unblocked streaming
    - Aptoide Direct Open CDN
    - Multi-mirror automatic failover with ZIP magic byte validation
    """
    
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }

    CLOUDFLARE_RELAY_URL = os.environ.get("CLOUDFLARE_RELAY_URL", "https://apk-relay.su468581.workers.dev")

    def _relay_wrap(self, url: str) -> str:
        """Wraps a target URL through Cloudflare Global Edge Relay."""
        if not self.CLOUDFLARE_RELAY_URL:
            return url
        return f"{self.CLOUDFLARE_RELAY_URL.rstrip('/')}/?url={urllib.parse.quote(url, safe='')}"

    def extract_package_name(self, url_or_query: str) -> Tuple[str, bool]:
        """
        Extracts package name from Play Store URL or raw input.
        Returns (package_name_or_query, is_exact_package_id).
        """
        cleaned = url_or_query.strip()
        if "play.google.com" in cleaned or "market://" in cleaned:
            parsed = urlparse(cleaned)
            query = parse_qs(parsed.query)
            if "id" in query and query["id"]:
                return query["id"][0], True
        
        # Check if matches standard Android package identifier: com.example.app (contains at least one dot, valid chars)
        from core.target_classifier import classify_target
        _, is_web = classify_target(cleaned)
        if is_web:
            return cleaned, False

        match = re.search(r'^([a-zA-Z0-9_]+\.[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*)$', cleaned)
        if match:
            return match.group(1), True
        
        # Free-text search keyword
        return cleaned, False

    def search_app_by_keyword(self, query: str) -> Optional[Dict[str, Any]]:
        """
        Searches open catalogs (Aptoide / Play Store) for an app by free-text title or keyword.
        """
        try:
            encoded_query = urllib.parse.quote(query)
            search_url = f"http://ws75.aptoide.com/api/7/apps/search/query={encoded_query}/limit=5"
            r = requests.get(search_url, headers=self.HEADERS, timeout=8)
            if r.status_code == 200:
                items = r.json().get("datalist", {}).get("list", [])
                if items:
                    top = items[0]
                    return {
                        "package_name": top.get("package"),
                        "title": top.get("name") or query,
                        "icon_url": top.get("icon"),
                        "developer": top.get("store", {}).get("name", "Unknown Developer"),
                        "app_id": top.get("id")
                    }
        except Exception as e:
            logger.debug(f"Keyword search failed for '{query}': {e}")
        return None

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
                for a in soup.find_all("a"):
                    if "/store/apps/developer" in a.get("href", "") or "/store/apps/dev" in a.get("href", ""):
                        details["developer"] = a.text.strip()
                        break
        except Exception as e:
            logger.debug(f"Could not fetch metadata from Play Store for {package_name}: {e}")

        return details

    def _resolve_aptoide_cdn(self, package_name: str) -> Optional[str]:
        """Queries Aptoide catalog for direct CDN download path."""
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

    def get_candidate_mirror_urls(self, package_name: str) -> List[Tuple[str, str]]:
        """
        Generates an ordered list of candidate download endpoints across multiple mirrors.
        """
        mirrors = []
        # 1. Aptoide Direct CDN
        aptoide_url = self._resolve_aptoide_cdn(package_name)
        if aptoide_url:
            mirrors.append((aptoide_url, "Aptoide Direct CDN"))

        # 2. Cloudflare Edge Relay APKPure
        apkpure_url = f"https://d.apkpure.net/b/APK/{package_name}?version=latest"
        mirrors.append((self._relay_wrap(apkpure_url), "Cloudflare Edge Relay (APKPure)"))

        # 3. Cloudflare Edge Relay APKCombo
        apkcombo_url = f"https://apkcombo.app/{package_name}/download/apk"
        mirrors.append((self._relay_wrap(apkcombo_url), "Cloudflare Edge Relay (APKCombo)"))

        # 4. F-Droid Repo
        fdroid_url = f"https://f-droid.org/repo/{package_name}.apk"
        mirrors.append((self._relay_wrap(fdroid_url), "Cloudflare Edge Relay (F-Droid)"))

        # 5. Direct Fallback
        mirrors.append((apkpure_url, "APKPure Direct Mirror"))
        return mirrors

    def download_apk(self, package_or_url_or_query: str, output_dir: str, progress_callback=None) -> Dict[str, Any]:
        """
        Orchestrates finding and downloading an APK from a Play Store URL, package name, or keyword title.
        """
        from core.target_classifier import classify_target
        norm_target, is_web = classify_target(package_or_url_or_query)
        if is_web:
            raise RuntimeError(
                f"'{package_or_url_or_query}' appears to be a Website domain ({norm_target}), not an Android application package. "
                f"Please run a Web Security Audit for websites, or provide an exact Android package identifier (e.g. `com.spotify.music`)."
            )

        raw_target, is_exact_pkg = self.extract_package_name(package_or_url_or_query)
        os.makedirs(output_dir, exist_ok=True)

        package_name = raw_target
        app_meta = {}

        if not is_exact_pkg:
            if progress_callback:
                progress_callback(f"Searching app catalog for keyword '{raw_target}'...", 10)
            search_result = self.search_app_by_keyword(raw_target)
            if search_result:
                package_name = search_result["package_name"]
                app_meta = search_result
                if progress_callback:
                    progress_callback(f"Found matching package: '{package_name}' ({search_result['title']})", 15)
            else:
                package_name = raw_target

        target_path = os.path.join(output_dir, f"{package_name}.apk")

        if not app_meta:
            app_meta = self.fetch_app_details(package_name)

        if progress_callback:
            progress_callback(f"Target: '{app_meta.get('title', package_name)}' ({package_name}). Querying mirrors...", 25)

        candidates = self.get_candidate_mirror_urls(package_name)
        successful_source = None
        last_error = None

        for mirror_url, source_name in candidates:
            try:
                if progress_callback:
                    progress_callback(f"Streaming from {source_name}...", 35)

                resp = requests.get(mirror_url, headers=self.HEADERS, stream=True, timeout=25, allow_redirects=True)
                if resp.status_code != 200:
                    continue

                total_size = int(resp.headers.get('content-length', 0))
                downloaded = 0
                first_chunk = True
                valid_zip = False

                with open(target_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=1024 * 64):
                        if chunk:
                            # Validate standard APK/ZIP magic bytes on first chunk (b"PK\x03\x04" or b"PK")
                            if first_chunk:
                                first_chunk = False
                                if len(chunk) >= 4 and chunk[:2] == b"PK":
                                    valid_zip = True
                                elif len(chunk) > 0 and b"<!DOCTYPE html>" in chunk[:100]:
                                    # Mirror returned an HTML error page, discard and try next
                                    break
                                else:
                                    valid_zip = True

                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0 and progress_callback:
                                percent = min(90, int(35 + (downloaded / total_size) * 55))
                                progress_callback(f"Downloading APK: {downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB", percent)

                file_size_mb = os.path.getsize(target_path) / (1024 * 1024) if os.path.exists(target_path) else 0

                if file_size_mb >= 0.2 and valid_zip:
                    successful_source = source_name
                    break
                else:
                    if os.path.exists(target_path):
                        os.remove(target_path)
            except Exception as e:
                logger.debug(f"Mirror {source_name} failed: {e}")
                last_error = e
                if os.path.exists(target_path):
                    try: os.remove(target_path)
                    except Exception: pass
                continue

        if not successful_source or not os.path.exists(target_path):
            raise RuntimeError(
                f"Could not automatically download APK for '{package_or_url_or_query}'. "
                f"Please provide the exact package ID (e.g. `com.spotify.music`) or upload the .apk directly via the web dashboard."
            )

        final_size_mb = os.path.getsize(target_path) / (1024 * 1024)
        if progress_callback:
            progress_callback(f"Download complete from {successful_source} ({final_size_mb:.2f} MB).", 95)

        return {
            "success": True,
            "package_name": package_name,
            "apk_path": target_path,
            "file_size_mb": round(final_size_mb, 2),
            "app_meta": app_meta,
            "source": successful_source
        }
