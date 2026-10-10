import os
import re
import ssl
import time
import json
import logging
import urllib.parse
import urllib.request
import http.client
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple, Set

from core.secret_classifier import SecretClassifier
from core.cloud_prober import CloudProber

logger = logging.getLogger("scanner.web_scanner")

class ScriptSrcParser(HTMLParser):
    """Extracts all script sources and inline script tags from HTML."""
    def __init__(self):
        super().__init__()
        self.script_srcs: List[str] = []
        self.inline_scripts: List[str] = []
        self.in_script: bool = False
        self.current_inline: List[str] = []
        self.title: Optional[str] = None
        self.in_title: bool = False
        self.meta_tags: List[Dict[str, str]] = []
        self.links: List[Dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): v for k, v in attrs if k}
        if tag == "script":
            if "src" in attr_dict and attr_dict["src"]:
                self.script_srcs.append(attr_dict["src"].strip())
            else:
                self.in_script = True
                self.current_inline = []
        elif tag == "title":
            self.in_title = True
        elif tag == "meta":
            self.meta_tags.append(attr_dict)
        elif tag == "link":
            self.links.append(attr_dict)

    def handle_endtag(self, tag):
        if tag == "script" and self.in_script:
            self.in_script = False
            content = "".join(self.current_inline).strip()
            if content:
                self.inline_scripts.append(content)
            self.current_inline = []
        elif tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_script:
            self.current_inline.append(data)
        elif self.in_title and not self.title:
            self.title = data.strip()


class WebsiteScanner:
    """
    Comprehensive Website & Web Application Security Auditor.
    Performs:
    1. HTTP Security Headers Audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.)
    2. Cookie Security Audit (Secure, HttpOnly, SameSite)
    3. Client-Side JavaScript Secret & API Key Classification
    4. Mixed Content & Insecure Transport Inspection
    5. CORS Misconfiguration Detection
    6. Framework & Frontend Library Identification (SCA)
    7. Passive Cloud Endpoint Probing (Firebase, S3, Supabase)
    """

    KNOWN_LIBRARIES = {
        "React": [r"react(?:\.production|\.development)?\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react-dom"],
        "Vue.js": [r"vue(?:\.runtime)?(?:\.min)?\.js", r"__VUE__", r"vuex", r"vue-router"],
        "Angular": [r"angular(?:\.min)?\.js", r"ng-version", r"@angular/core"],
        "Next.js": [r"/_next/static/", r"__NEXT_DATA__"],
        "Nuxt.js": [r"/_nuxt/", r"__NUXT__"],
        "jQuery": [r"jquery(?:-([0-9\.]+))?(?:\.min)?\.js", r"jQuery\s*v([0-9\.]+)"],
        "Bootstrap": [r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)", r"bootstrap\s*v([0-9\.]+)"],
        "Tailwind CSS": [r"tailwindcss", r"tailwind\.min\.css"],
        "Lodash / Underscore": [r"lodash(?:\.min)?\.js", r"underscore(?:\.min)?\.js"],
        "Axios": [r"axios(?:\.min)?\.js"],
        "Webpack": [r"webpackChunk", r"webpackJsonp"],
        "Vite": [r"/@vite/client", r"vite/client"],
        "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
        "Cloudflare": [r"cf-ray", r"cloudflare-static", r"__cf_bm"]
    }

    def __init__(self):
        self.secret_classifier = SecretClassifier()
        self.cloud_prober = CloudProber()
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 (SecurityAuditBot/1.0)"

    def _normalize_url(self, raw_url: str) -> str:
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def fetch_url(self, target_url: str, timeout: int = 12) -> Dict[str, Any]:
        """Fetches the target URL with redirect following and header capture."""
        context = ssl.create_default_context()
        # In audit mode, we permit inspection even if self-signed cert
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        )

        start_time = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
                elapsed_ms = int((time.time() - start_time) * 1000)
                final_url = response.geturl()
                status_code = response.getcode()
                headers = dict(response.info())
                # Normalize header keys to lowercase
                headers_lower = {k.lower(): v for k, v in headers.items()}
                raw_headers = response.getheaders() if hasattr(response, "getheaders") else []
                body_bytes = response.read(10 * 1024 * 1024) # Cap at 10MB
                body_text = body_bytes.decode("utf-8", errors="ignore")

                return {
                    "success": True,
                    "initial_url": target_url,
                    "final_url": final_url,
                    "status_code": status_code,
                    "elapsed_ms": elapsed_ms,
                    "headers": headers_lower,
                    "raw_headers": raw_headers,
                    "body": body_text,
                    "error": None
                }
        except Exception as e:
            return {
                "success": False,
                "initial_url": target_url,
                "final_url": target_url,
                "status_code": 0,
                "elapsed_ms": int((time.time() - start_time) * 1000),
                "headers": {},
                "raw_headers": [],
                "body": "",
                "error": str(e)
            }

    def audit_security_headers(self, headers: Dict[str, str], final_url: str) -> List[Dict[str, Any]]:
        """Audits HTTP response headers for missing or misconfigured security controls."""
        findings = []
        is_https = final_url.startswith("https://")

        # 1. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        if not hsts and is_https:
            findings.append({
                "id": "WEB-HSTS-001",
                "category": "Transport Security (HSTS)",
                "title": "Missing Strict-Transport-Security (HSTS) Header",
                "severity": "HIGH",
                "confidence": 1.0,
                "exposure": "Network-level downgrade / SSL stripping",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": "Strict-Transport-Security header absent",
                    "context_snippet": f"URL: {final_url}\nProtocol: HTTPS\nMissing: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                },
                "impact": "Browsers may connect via unencrypted HTTP on the first visit, enabling Man-in-the-Middle (MitM) attackers to strip SSL and intercept session credentials.",
                "remediation": "Add the header 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server config (Nginx/Apache/Cloudflare)."
            })
        elif hsts:
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 10368000: # Less than 120 days
                    findings.append({
                        "id": "WEB-HSTS-002",
                        "category": "Transport Security (HSTS)",
                        "title": "Short HSTS max-age Duration",
                        "severity": "MEDIUM",
                        "confidence": 0.95,
                        "exposure": "Premature HSTS policy expiration",
                        "evidence": {
                            "file": "HTTP Response Headers",
                            "line": 1,
                            "detected_preview": f"Strict-Transport-Security: {hsts}",
                            "context_snippet": f"Current max-age: {max_age}s (< 10368000s recommended)"
                        },
                        "impact": "Short HSTS expiration limits long-term protection against protocol downgrade attacks.",
                        "remediation": "Increase max-age to at least 1 year (31536000 seconds) and consider adding includeSubDomains and preload."
                    })

        # 2. Content-Security-Policy (CSP)
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append({
                "id": "WEB-CSP-001",
                "category": "Content Security Policy (CSP)",
                "title": "Missing Content-Security-Policy (CSP)",
                "severity": "HIGH",
                "confidence": 1.0,
                "exposure": "Cross-Site Scripting (XSS) & Clickjacking",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": "Content-Security-Policy header absent",
                    "context_snippet": f"URL: {final_url}\nMissing: Content-Security-Policy: default-src 'self'; script-src 'self'..."
                },
                "impact": "Without CSP, the browser has no restrictions on where executable scripts, images, and styles can be loaded from, greatly increasing XSS and data exfiltration severity.",
                "remediation": "Define and deploy a strict Content-Security-Policy restricting script-src, object-src, and frame-ancestors."
            })
        else:
            if "'unsafe-inline'" in csp and "nonce-" not in csp:
                findings.append({
                    "id": "WEB-CSP-002",
                    "category": "Content Security Policy (CSP)",
                    "title": "Unsafe Inline Script Execution in CSP",
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "exposure": "Weakened XSS mitigation",
                    "evidence": {
                        "file": "HTTP Response Headers",
                        "line": 1,
                        "detected_preview": csp[:120] + "...",
                        "context_snippet": f"Content-Security-Policy: {csp}"
                    },
                    "impact": "The 'unsafe-inline' directive allows arbitrary inline script tags to execute, bypassing primary CSP protections against Reflected and Stored XSS.",
                    "remediation": "Migrate inline scripts to external bundled scripts or protect them with cryptographic nonces (nonce-...) or SHA-256 hashes."
                })
            if "'unsafe-eval'" in csp:
                findings.append({
                    "id": "WEB-CSP-003",
                    "category": "Content Security Policy (CSP)",
                    "title": "Unsafe Dynamic Code Evaluation in CSP ('unsafe-eval')",
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "exposure": "Permits eval() and string-to-code execution",
                    "evidence": {
                        "file": "HTTP Response Headers",
                        "line": 1,
                        "detected_preview": csp[:120] + "...",
                        "context_snippet": f"Content-Security-Policy: {csp}"
                    },
                    "impact": "Allows client-side use of eval(), Function(), and setTimeout with string arguments, facilitating DOM-based XSS payload execution.",
                    "remediation": "Refactor codebase to eliminate dynamic eval() calls and remove 'unsafe-eval' from your CSP."
                })

        # 3. X-Frame-Options (Clickjacking)
        x_frame = headers.get("x-frame-options", "").upper()
        if not x_frame and (not csp or "frame-ancestors" not in csp):
            findings.append({
                "id": "WEB-FRAME-001",
                "category": "Clickjacking Protection",
                "title": "Missing X-Frame-Options / frame-ancestors Header",
                "severity": "MEDIUM",
                "confidence": 1.0,
                "exposure": "UI Redressing / Clickjacking attack surface",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": "X-Frame-Options header absent",
                    "context_snippet": f"URL: {final_url}\nMissing: X-Frame-Options: DENY or SAMEORIGIN"
                },
                "impact": "Attackers can embed your website in a transparent iframe on a malicious website to trick authenticated users into clicking unauthorized actions (Clickjacking).",
                "remediation": "Set 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY', or define 'frame-ancestors 'self'' in CSP."
            })

        # 4. X-Content-Type-Options (MIME Sniffing)
        x_content_type = headers.get("x-content-type-options", "").lower()
        if "nosniff" not in x_content_type:
            findings.append({
                "id": "WEB-MIME-001",
                "category": "MIME Confusion Defense",
                "title": "Missing X-Content-Type-Options Header",
                "severity": "MEDIUM",
                "confidence": 1.0,
                "exposure": "MIME sniffing & drive-by script execution",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": "X-Content-Type-Options: nosniff absent",
                    "context_snippet": f"URL: {final_url}\nMissing: X-Content-Type-Options: nosniff"
                },
                "impact": "Browsers may attempt to infer the MIME type of a file based on its content rather than the declared Content-Type header, allowing non-executable uploads (e.g. .jpg) to execute as HTML/JS.",
                "remediation": "Add 'X-Content-Type-Options: nosniff' header across all HTTP responses."
            })

        # 5. Referrer-Policy
        ref_policy = headers.get("referrer-policy", "").lower()
        if not ref_policy or ref_policy in ["unsafe-url", "no-referrer-when-downgrade"]:
            findings.append({
                "id": "WEB-REF-001",
                "category": "Information Disclosure",
                "title": "Weak or Missing Referrer-Policy Header",
                "severity": "LOW",
                "confidence": 0.90,
                "exposure": "URL parameter leakage in HTTP Referer",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": f"Referrer-Policy: {ref_policy or 'Absent'}",
                    "context_snippet": f"Current: {ref_policy or 'Not configured'}\nRecommended: strict-origin-when-cross-origin"
                },
                "impact": "Sensitive path segments or query parameters (e.g. password reset tokens, user IDs) may be leaked to external third-party domains via the Referer header.",
                "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
            })

        # 6. Server Banner / Technology Exposure
        server_header = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        aspnet_version = headers.get("x-aspnet-version", "")
        exposed_banners = [b for b in [server_header, powered_by, aspnet_version] if b]

        if exposed_banners and any(re.search(r"\d+\.\d+", b) for b in exposed_banners):
            findings.append({
                "id": "WEB-INFO-001",
                "category": "Information Disclosure",
                "title": "Detailed Server Version Banner Exposure",
                "severity": "LOW",
                "confidence": 0.95,
                "exposure": "Server & backend runtime version disclosure",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": f"Server: {server_header} | X-Powered-By: {powered_by}",
                    "context_snippet": f"Server: {server_header}\nX-Powered-By: {powered_by}\nX-AspNet-Version: {aspnet_version}"
                },
                "impact": "Exact version numbers allow attackers to map specific known CVE vulnerabilities against your web server or application framework.",
                "remediation": "Disable server version tokens (e.g., 'server_tokens off;' in Nginx, or remove 'X-Powered-By' header in Express/PHP/ASP.NET)."
            })

        # 7. CORS Misconfiguration Check
        cors_origin = headers.get("access-control-allow-origin", "")
        cors_credentials = headers.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*" and cors_credentials == "true":
            findings.append({
                "id": "WEB-CORS-001",
                "category": "Cross-Origin Resource Sharing (CORS)",
                "title": "Critical CORS Misconfiguration: Wildcard with Credentials",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "exposure": "Cross-origin authenticated data theft",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                    "context_snippet": f"Access-Control-Allow-Origin: {cors_origin}\nAccess-Control-Allow-Credentials: {cors_credentials}"
                },
                "impact": "Any malicious website in the user's browser can perform cross-origin XMLHttpRequests/fetch to read private authenticated user data.",
                "remediation": "Explicitly whitelist trusted origins rather than using a wildcard, or disable Access-Control-Allow-Credentials."
            })
        elif cors_origin == "*":
            findings.append({
                "id": "WEB-CORS-002",
                "category": "Cross-Origin Resource Sharing (CORS)",
                "title": "Permissive CORS Wildcard (Access-Control-Allow-Origin: *)",
                "severity": "LOW",
                "confidence": 0.85,
                "exposure": "Public cross-origin API read access",
                "evidence": {
                    "file": "HTTP Response Headers",
                    "line": 1,
                    "detected_preview": "Access-Control-Allow-Origin: *",
                    "context_snippet": f"Access-Control-Allow-Origin: {cors_origin}"
                },
                "impact": "Allows any origin to read the response. Acceptable for public content, but dangerous if returning private user state.",
                "remediation": "If this endpoint serves private user data, validate and restrict the Origin header to authorized domains."
            })

        return findings

    def audit_cookies(self, raw_headers: List[Tuple[str, str]], final_url: str) -> List[Dict[str, Any]]:
        """Audits Set-Cookie headers for Secure, HttpOnly, and SameSite attributes."""
        findings = []
        is_https = final_url.startswith("https://")

        cookie_headers = [v for k, v in raw_headers if k.lower() == "set-cookie"]
        for cookie_str in cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue
            cookie_name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
            cookie_flags = [p.lower() for p in parts[1:]]

            has_secure = any(f == "secure" for f in cookie_flags)
            has_httponly = any(f == "httponly" for f in cookie_flags)
            samesite_part = next((f for f in cookie_flags if f.startswith("samesite")), None)

            # 1. Missing Secure Flag
            if not has_secure and is_https:
                findings.append({
                    "id": "WEB-COOKIE-001",
                    "category": "Session & Cookie Security",
                    "title": f"Missing 'Secure' Flag on Cookie '{cookie_name}'",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "exposure": "Cleartext transmission of session cookies",
                    "evidence": {
                        "file": "Set-Cookie Header",
                        "line": 1,
                        "detected_preview": cookie_str[:80] + "...",
                        "context_snippet": f"Set-Cookie: {cookie_str}\nMissing: 'Secure' attribute"
                    },
                    "impact": "If a user is downgraded to HTTP or visits an unencrypted link on your domain, the browser will transmit this cookie over cleartext, allowing session hijacking.",
                    "remediation": f"Append '; Secure' to the Set-Cookie directive for '{cookie_name}'."
                })

            # 2. Missing HttpOnly Flag
            if not has_httponly:
                findings.append({
                    "id": "WEB-COOKIE-002",
                    "category": "Session & Cookie Security",
                    "title": f"Missing 'HttpOnly' Flag on Cookie '{cookie_name}'",
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "exposure": "Accessible to client-side JavaScript / XSS",
                    "evidence": {
                        "file": "Set-Cookie Header",
                        "line": 1,
                        "detected_preview": cookie_str[:80] + "...",
                        "context_snippet": f"Set-Cookie: {cookie_str}\nMissing: 'HttpOnly' attribute"
                    },
                    "impact": "Any XSS flaw on your domain can read this cookie via 'document.cookie' and exfiltrate authentication tokens.",
                    "remediation": f"Set '; HttpOnly' on cookie '{cookie_name}' unless explicit client-side JS read access is required."
                })

            # 3. Missing or Weak SameSite
            if not samesite_part or "samesite=none" in samesite_part:
                findings.append({
                    "id": "WEB-COOKIE-003",
                    "category": "Session & Cookie Security",
                    "title": f"Missing or Permissive SameSite Attribute on Cookie '{cookie_name}'",
                    "severity": "MEDIUM",
                    "confidence": 0.90,
                    "exposure": "Cross-Site Request Forgery (CSRF)",
                    "evidence": {
                        "file": "Set-Cookie Header",
                        "line": 1,
                        "detected_preview": cookie_str[:80] + "...",
                        "context_snippet": f"Set-Cookie: {cookie_str}\nSameSite: {samesite_part or 'Not set'}"
                    },
                    "impact": "Without SameSite=Lax or SameSite=Strict, cross-site requests (e.g. malicious form posts) will automatically include this cookie, creating CSRF risk.",
                    "remediation": f"Add '; SameSite=Lax' (or SameSite=Strict) to the Set-Cookie directive for '{cookie_name}'."
                })

        return findings

    def check_mixed_content(self, html_body: str, final_url: str) -> List[Dict[str, Any]]:
        """Checks for mixed content (insecure HTTP resources embedded in HTTPS pages)."""
        findings = []
        if not final_url.startswith("https://"):
            return findings

        # Look for http:// resources
        patterns = [
            (r"""<script[^>]+src=["'](http://[^"']+)["']""", "Active Mixed Content (Script)", "HIGH", "Permits MitM script tampering and complete page takeover"),
            (r"""<link[^>]+rel=["']stylesheet["'][^>]+href=["'](http://[^"']+)["']""", "Active Mixed Content (Stylesheet)", "HIGH", "Permits stylesheet hijacking and UI redressing"),
            (r"""<iframe[^>]+src=["'](http://[^"']+)["']""", "Active Mixed Content (Iframe)", "HIGH", "Embeds unencrypted frame within secure session"),
            (r"""<img[^>]+src=["'](http://[^"']+)["']""", "Passive Mixed Content (Image)", "LOW", "Allows network eavesdroppers to view/replace images"),
        ]

        for pat, title, severity, impact in patterns:
            matches = list(re.finditer(pat, html_body, re.IGNORECASE))
            for m in matches[:5]: # Cap per pattern
                insecure_url = m.group(1)
                findings.append({
                    "id": "WEB-MIXED-001",
                    "category": "Mixed Content",
                    "title": f"{title}: {urllib.parse.urlparse(insecure_url).netloc}",
                    "severity": severity,
                    "confidence": 1.0,
                    "exposure": "Insecure HTTP resource loaded over HTTPS",
                    "evidence": {
                        "file": "HTML DOM",
                        "line": html_body[:m.start()].count("\n") + 1,
                        "detected_preview": insecure_url,
                        "context_snippet": m.group(0)
                    },
                    "impact": impact,
                    "remediation": f"Update the resource URL from '{insecure_url}' to 'https://' or use protocol-relative '//'."
                })

        return findings

    def scan_js_bundles(self, script_urls: List[str], base_url: str, max_scripts: int = 12) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Downloads and scans client-side JavaScript bundles for leaked secrets and detects frontend frameworks.
        """
        all_findings = []
        detected_tech = set()
        vulnerabilities = []

        # Resolve relative script URLs to absolute URLs
        resolved_urls = []
        for s in script_urls:
            full = urllib.parse.urljoin(base_url, s)
            if full not in resolved_urls:
                resolved_urls.append(full)

        resolved_urls = resolved_urls[:max_scripts]

        def fetch_and_scan(url: str):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=10, context=context) as resp:
                    code = resp.read(5 * 1024 * 1024).decode("utf-8", errors="ignore")
                    
                    # 1. Run Secret Classifier
                    script_findings = self.secret_classifier.scan_text(code, file_path=url)
                    
                    # 2. Check for known libraries
                    lib_matches = []
                    for lib_name, patterns in self.KNOWN_LIBRARIES.items():
                        for pat in patterns:
                            if re.search(pat, code, re.IGNORECASE) or re.search(pat, url, re.IGNORECASE):
                                lib_matches.append(lib_name)
                                break

                    # 3. Check for vulnerable jQuery versions (< 3.5.0)
                    jq_match = re.search(r"jQuery\s*v?([0-9\.]+)", code, re.IGNORECASE) or re.search(r"jquery[/-]([0-9\.]+)", url, re.IGNORECASE)
                    if jq_match:
                        ver = jq_match.group(1)
                        try:
                            ver_parts = [int(p) for p in ver.split(".")[:2]]
                            if ver_parts[0] < 3 or (ver_parts[0] == 3 and ver_parts[1] < 5):
                                vulnerabilities.append({
                                    "id": "SCA-JQUERY-001",
                                    "category": "Vulnerable Third-Party Library (SCA)",
                                    "title": f"Outdated / Vulnerable jQuery Library (v{ver})",
                                    "severity": "HIGH",
                                    "confidence": 0.95,
                                    "exposure": "Known Cross-Site Scripting (CVE-2020-11022 / CVE-2020-11023)",
                                    "evidence": {
                                        "file": url,
                                        "line": 1,
                                        "detected_preview": f"jQuery v{ver}",
                                        "context_snippet": f"Detected jQuery v{ver} in bundle: {url}"
                                    },
                                    "impact": "jQuery versions prior to 3.5.0 contain multiple XSS vulnerabilities in htmlPrefilter passing untrusted HTML containing <option> tags.",
                                    "remediation": f"Upgrade jQuery to version 3.7.1 or later or remove direct jQuery dependencies."
                                })
                        except Exception:
                            pass

                    return script_findings, lib_matches
            except Exception as e:
                logger.debug(f"Error fetching script {url}: {e}")
                return [], []

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(fetch_and_scan, u): u for u in resolved_urls}
            for future in as_completed(future_to_url):
                try:
                    f_findings, f_libs = future.result()
                    all_findings.extend(f_findings)
                    detected_tech.update(f_libs)
                except Exception as e:
                    logger.debug(f"Worker exception: {e}")

        all_findings.extend(vulnerabilities)
        return all_findings, {"detected_libraries": list(detected_tech), "scripts_scanned": len(resolved_urls)}

    def audit_website(self, target_url: str, progress_callback=None) -> Dict[str, Any]:
        """
        Runs a complete end-to-end security audit on a website.
        """
        normalized_url = self._normalize_url(target_url)
        domain = urllib.parse.urlparse(normalized_url).netloc

        def log_pct(msg: str, pct: int):
            logger.info(f"[{pct}%] {msg}")
            if progress_callback:
                progress_callback(msg, pct)

        log_pct(f"Connecting to web target '{normalized_url}'...", 10)
        fetch_res = self.fetch_url(normalized_url)

        if not fetch_res["success"]:
            raise RuntimeError(f"Unable to reach website {normalized_url}: {fetch_res['error']}")

        final_url = fetch_res["final_url"]
        headers = fetch_res["headers"]
        raw_headers = fetch_res["raw_headers"]
        body = fetch_res["body"]

        # Parse HTML
        log_pct("Parsing HTML structure, meta tags & DOM scripts...", 25)
        parser = ScriptSrcParser()
        try:
            parser.feed(body)
        except Exception:
            pass

        app_title = parser.title or domain
        server_info = headers.get("server") or headers.get("x-powered-by") or "Cloudflare / Reverse Proxy"

        # 1. Audit HTTP Security Headers
        log_pct("Auditing HTTP security headers (HSTS, CSP, X-Frame, CORS)...", 40)
        header_findings = self.audit_security_headers(headers, final_url)

        # 2. Audit Cookies
        log_pct("Analyzing session cookies, Secure & SameSite attributes...", 55)
        cookie_findings = self.audit_cookies(raw_headers, final_url)

        # 3. Audit Mixed Content
        log_pct("Checking for active & passive mixed content over HTTPS...", 65)
        mixed_findings = self.check_mixed_content(body, final_url)

        # 4. Scan JavaScript Bundles for Leaked Secrets & API Keys
        log_pct("Crawling & scanning client-side JavaScript bundles for credentials...", 75)
        js_findings, js_meta = self.scan_js_bundles(parser.script_srcs, final_url)

        # Also scan inline scripts
        for idx, inline_code in enumerate(parser.inline_scripts[:10]):
            inline_findings = self.secret_classifier.scan_text(inline_code, file_path=f"Inline Script #{idx+1}")
            js_findings.extend(inline_findings)

        # 5. Passive Cloud Probing
        log_pct("Probing referenced cloud storage and BaaS databases...", 85)
        all_snippets = " ".join([f.get("evidence", {}).get("context_snippet", "") for f in js_findings if isinstance(f, dict)]) + " " + body[:50000]
        cloud_findings, cloud_diagnostics = self.cloud_prober.probe_text_for_cloud_resources(all_snippets)

        # Compile all findings
        all_findings = []
        all_findings.extend(header_findings)
        all_findings.extend(cookie_findings)
        all_findings.extend(mixed_findings)
        all_findings.extend(js_findings)
        all_findings.extend(cloud_findings)

        # Detect Frameworks from HTML meta tags + JS scan
        detected_tech = set(js_meta.get("detected_libraries", []))
        for lib_name, patterns in self.KNOWN_LIBRARIES.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE) or re.search(pat, str(headers), re.IGNORECASE):
                    detected_tech.add(lib_name)
                    break

        primary_framework = "Web Application"
        if detected_tech:
            primary_framework = f"Web ({', '.join(sorted(list(detected_tech))[:3])})"

        app_info = {
            "package": domain,
            "title": app_title,
            "developer": domain,
            "icon_url": f"https://www.google.com/s2/favicons?domain={domain}&sz=128",
            "version_name": f"HTTP {fetch_res['status_code']}",
            "version_code": "Web",
            "min_sdk": "TLS 1.2 / 1.3",
            "target_sdk": headers.get("server", "Web Server"),
            "file_size_mb": round(len(body.encode('utf-8')) / (1024 * 1024), 3),
            "url": final_url,
            "domain": domain,
            "response_time_ms": fetch_res["elapsed_ms"],
            "is_web": True
        }

        tech_info = {
            "primary_framework": primary_framework,
            "framework_details": f"Web Application running on {headers.get('server', 'Standard Web Server')}",
            "detected_sdks": [{"name": t, "category": "Frontend Framework / Infrastructure"} for t in detected_tech],
            "native_architectures": ["WebAssembly / JS"],
            "native_libraries_count": len(parser.script_srcs),
            "has_hermes_engine": False,
            "is_hybrid": False,
            "server": headers.get("server", "Unknown"),
            "scripts_scanned": js_meta.get("scripts_scanned", 0)
        }

        return {
            "app_info": app_info,
            "tech_info": tech_info,
            "findings": all_findings,
            "cloud_diagnostics": cloud_diagnostics,
            "raw_fetch": fetch_res
        }
