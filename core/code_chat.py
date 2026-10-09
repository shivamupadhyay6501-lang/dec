import os
import re
import json
import logging
import requests
from typing import Dict, Any, List, Optional
from database.db import AuditDatabase

logger = logging.getLogger("scanner.code_chat")

class AppCodeChatAssistant:
    """
    RAG-powered conversational engine that enables developers and auditors
    to chat with any decompiled APK codebase or audited website.
    Performs deep search, extracts precise code snippets, and synthesizes answers.
    """

    def __init__(self, workspace_dir: Optional[str] = None):
        if workspace_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.workspace_dir = os.path.join(base_dir, "workspace")
        else:
            self.workspace_dir = workspace_dir

        self.db = AuditDatabase()

    def get_suggested_prompts(self, scan_id: str) -> List[str]:
        """Returns context-aware starter prompts for a given scan."""
        report = self.db.get_scan(scan_id)
        if not report:
            return [
                "Show all API endpoints and network URLs used in this app",
                "Where are API keys, tokens, and secrets stored in the code?",
                "Analyze AndroidManifest.xml permissions and exported components",
                "How is user login and session data handled?",
                "Explain the cryptography and hashing algorithms used"
            ]

        is_web = report.get("scan_type") == "web" or "domain" in report.get("app_info", {})
        if is_web:
            return [
                "Summarize the missing security headers and how to fix them",
                "List all client-side JavaScript API tokens found",
                "What are the CORS and Cookie security risks on this site?",
                "Provide Nginx/Apache configuration snippets to fix findings"
            ]

        framework = report.get("tech_info", {}).get("primary_framework", "Native Android")
        return [
            f"Show all network endpoints and Base URLs used in this {framework} app",
            "Where are API keys, tokens, and secrets initialized in code?",
            "Analyze AndroidManifest.xml permissions and exported activities",
            "Is user authentication data stored securely in SharedPreferences or EncryptedSharedPreferences?",
            "Explain cryptography and hash functions found in the source code"
        ]

    def _search_decompiled_sources(self, scan_id: str, query: str) -> List[Dict[str, Any]]:
        """
        Scans decompiled Java/Kotlin source files and resources for code relevant to the user's query.
        """
        scan_dir = os.path.join(self.workspace_dir, scan_id)
        sources_dir = os.path.join(scan_dir, "decompiled", "sources")
        manifest_path = os.path.join(scan_dir, "decompiled", "resources", "AndroidManifest.xml")

        extracted_snippets = []

        # 1. If asking about manifest/permissions
        if any(w in query.lower() for w in ["manifest", "permission", "exported", "activity", "receiver", "service", "intent"]):
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        extracted_snippets.append({
                            "file": "resources/AndroidManifest.xml",
                            "line_start": 1,
                            "line_end": min(len(lines), 60),
                            "content": "".join(lines[:60]),
                            "relevance": "Android Application Security Configuration"
                        })
                except Exception as e:
                    logger.debug(f"Could not read manifest: {e}")

        # 2. Extract keywords from query
        clean_query = re.sub(r'[^a-zA-Z0-9_\s]', ' ', query.lower())
        tokens = [t for t in clean_query.split() if len(t) > 3 and t not in ["where", "what", "show", "tell", "this", "explain", "code", "used", "does", "have", "with", "from"]]

        # Add domain-specific keywords based on query intent
        query_lower = query.lower()
        if "api" in query_lower or "endpoint" in query_lower or "url" in query_lower or "network" in query_lower:
            tokens.extend(["http", "https", "retrofit", "okhttp", "base_url", "url", "client", "endpoint", "api"])
        if "secret" in query_lower or "key" in query_lower or "token" in query_lower or "password" in query_lower:
            tokens.extend(["key", "token", "secret", "password", "bearer", "api_key", "auth"])
        if "storage" in query_lower or "login" in query_lower or "auth" in query_lower or "user" in query_lower:
            tokens.extend(["sharedpreferences", "encryptedsharedpreferences", "keystore", "room", "sqlite", "database", "login", "auth"])
        if "crypto" in query_lower or "hash" in query_lower or "encrypt" in query_lower:
            tokens.extend(["aes", "des", "cipher", "messagedigest", "sha-256", "md5", "secretkeyspec", "ivparameterspec"])

        token_set = set(tokens)

        if not os.path.exists(sources_dir):
            return extracted_snippets

        matches_found = 0
        for root, _, files in os.walk(sources_dir):
            if matches_found >= 6:
                break
            for file in files:
                if not file.endswith((".java", ".kt", ".xml", ".json")):
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, scan_dir).replace("\\", "/")

                # Skip common android support noisy libraries
                if any(noise in rel_path.lower() for noise in ["androidx/core", "google/android/gms", "kotlin/", "io/reactivex"]):
                    continue

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    matching_line_indices = []
                    for idx, line in enumerate(lines):
                        line_lower = line.lower()
                        for tok in token_set:
                            if tok in line_lower:
                                matching_line_indices.append(idx)
                                break

                    if matching_line_indices:
                        # Pick best snippet cluster
                        first_match = matching_line_indices[0]
                        start_line = max(0, first_match - 4)
                        end_line = min(len(lines), first_match + 15)
                        snippet_code = "".join(lines[start_line:end_line])

                        extracted_snippets.append({
                            "file": rel_path,
                            "line_start": start_line + 1,
                            "line_end": end_line,
                            "content": snippet_code,
                            "matched_keywords": [t for t in token_set if t in snippet_code.lower()]
                        })
                        matches_found += 1
                        if matches_found >= 6:
                            break
                except Exception as e:
                    logger.debug(f"Error reading file {full_path}: {e}")

        return extracted_snippets

    def answer_query(self, scan_id: str, query: str, gemini_api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Synthesizes an intelligent, structured response to a code/security question
        about the audited target.
        """
        report = self.db.get_scan(scan_id)
        if not report:
            return {
                "answer": f"⚠️ Scan report `{scan_id}` not found in the database. Please perform an audit first.",
                "snippets": [],
                "scan_id": scan_id
            }

        app_info = report.get("app_info", {})
        tech_info = report.get("tech_info", {})
        findings = report.get("findings", [])
        cloud_diag = report.get("cloud_diagnostics", [])

        # Retrieve matching code snippets from decompiled tree
        snippets = self._search_decompiled_sources(scan_id, query)

        # Build prompt context
        target_name = app_info.get("domain") or app_info.get("package") or app_info.get("title", "Target App")
        findings_summary = [f"[{f.get('severity')}] {f.get('title')}: {f.get('exposure') or f.get('impact')}" for f in findings[:10]]

        # Try Gemini Synthesis
        api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if api_key:
            try:
                system_prompt = f"""You are an elite Mobile & Web Security Expert and Reverse Engineering Assistant.
Target Application: {target_name}
Framework: {tech_info.get('primary_framework', 'Native')}
Security Score: {report.get('score_data', {}).get('score', 'N/A')}/100

Extracted Code Snippets from Decompiled Sources:
{json.dumps(snippets, indent=2)}

Top Security Findings:
{json.dumps(findings_summary, indent=2)}

Live Cloud / Firebase Diagnostics:
{json.dumps(cloud_diag, indent=2)}

User Question: "{query}"

Answer the user's question with precise technical accuracy.
Reference specific file names and line numbers from the decompiled snippets.
Include Markdown code blocks with syntax highlighting where helpful.
Highlight any security risks, OWASP MASVS/Top 10 implications, and practical remediation steps."""

                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
                payload = {
                    "contents": [{"parts": [{"text": system_prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048}
                }
                r = requests.post(url, json=payload, timeout=20)
                if r.status_code == 200:
                    resp_json = r.json()
                    candidate = resp_json.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text")
                    if candidate:
                        return {
                            "answer": candidate,
                            "snippets": snippets,
                            "scan_id": scan_id,
                            "ai_powered": True
                        }
            except Exception as e:
                logger.warning(f"Gemini chat synthesis failed: {e}. Using intelligent heuristic code synthesizer.")

        # Heuristic Code Search & Synthesis Fallback
        return self._heuristic_code_answer(query, target_name, tech_info, snippets, findings, cloud_diag, scan_id)

    def _heuristic_code_answer(self, query: str, target: str, tech_info: dict, snippets: list, findings: list, cloud_diag: list, scan_id: str) -> Dict[str, Any]:
        """Generates a structured, accurate analysis when offline or when Gemini quota is exceeded."""
        query_lower = query.lower()
        parts = []

        parts.append(f"### 🔍 Deep Code Analysis for: **{target}**")
        parts.append(f"**Framework:** `{tech_info.get('primary_framework', 'Native Android')}` | **Question:** *\"{query}\"*\n")

        if "firebase" in query_lower or "cloud" in query_lower or "bucket" in query_lower or "database" in query_lower:
            parts.append("#### ☁️ Cloud & Firebase Security Status:")
            if cloud_diag:
                for diag in cloud_diag:
                    parts.append(f"- **{diag.get('service')}:** `{diag.get('target_url')}`")
                    parts.append(f"  - **Verdict:** `{diag.get('verdict_badge')}` (Status: {diag.get('status_code')})")
                    parts.append(f"  - *Details:* {diag.get('details')}")
            else:
                parts.append("No active external Firebase or cloud bucket misconfigurations were detected during this scan.")
            parts.append("")

        if snippets:
            parts.append(f"#### 📂 Relevant Decompiled Source Snippets ({len(snippets)} matched files):")
            for idx, snip in enumerate(snippets, 1):
                parts.append(f"**{idx}. File: `{snip['file']}` (Lines {snip['line_start']}-{snip['line_end']})**")
                parts.append(f"```java\n{snip['content'].strip()}\n```\n")
        else:
            parts.append("ℹ️ *No direct matching source code lines were found in the decompiled classes for this query. The app may be using native `.so` libraries or standard SDK defaults.*")

        # Related findings
        matching_findings = [f for f in findings if any(k in f.get('title', '').lower() or k in f.get('category', '').lower() for k in query_lower.split())]
        if matching_findings:
            parts.append("#### ⚠️ Related Vulnerability Findings from Audit:")
            for mf in matching_findings[:3]:
                parts.append(f"- **[{mf.get('severity')}] {mf.get('title')}**")
                parts.append(f"  - *Impact:* {mf.get('impact') or mf.get('exposure')}")
                parts.append(f"  - *Remediation:* {mf.get('remediation')}")

        return {
            "answer": "\n".join(parts),
            "snippets": snippets,
            "scan_id": scan_id,
            "ai_powered": False
        }
