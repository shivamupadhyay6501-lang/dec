import os
import re
import json
import logging
import requests
from typing import Dict, Any, List, Optional
from database.db import AuditDatabase

logger = logging.getLogger("scanner.code_chat")

def _load_env_if_missing():
    if not os.environ.get("GEMINI_API_KEY"):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env_file = os.path.join(base_dir, ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() in ("GEMINI_API_KEY", "GOOGLE_API_KEY") and not os.environ.get(k.strip()):
                                os.environ[k.strip()] = v.strip()
            except Exception:
                pass

_load_env_if_missing()

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

                # Skip common noisy third-party libraries unless explicitly queried
                noise_patterns = ["androidx/", "android/support/", "google/android/", "kotlin/", "kotlinx/", "io/reactivex", "com/itextpdf", "org/bouncycastle", "com/airbnb/lottie"]
                if not any(np in query.lower() for np in ["androidx", "support", "kotlin", "lottie"]) and any(noise in rel_path.lower() for noise in noise_patterns):
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

        # Extract discovered secrets and credentials
        secrets_list = []
        for f in findings:
            ev = f.get("evidence", {})
            sec_val = ev.get("matched_secret") or ev.get("detected_preview")
            cat = (f.get("category") or "").lower()
            tit = (f.get("title") or "").lower()
            if sec_val and ("secret" in cat or "credential" in cat or "key" in cat or "token" in tit or "secret" in tit or "key" in tit):
                secrets_list.append({
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "file": ev.get("file"),
                    "line": ev.get("line"),
                    "secret_value": sec_val
                })

        # Compact snippets for Gemini context (max 3 snippets, max 35 lines each)
        compact_snippets = []
        for s in snippets[:3]:
            content_lines = s.get("content", "").splitlines()[:35]
            compact_snippets.append({
                "file": s.get("file"),
                "lines": f"{s.get('line_start')}-{min(s.get('line_end', 0), s.get('line_start', 1) + 35)}",
                "code": "\n".join(content_lines)
            })

        # Build prompt context
        target_name = app_info.get("domain") or app_info.get("package") or app_info.get("title", "Target App")
        findings_summary = [f"[{f.get('severity')}] {f.get('title')}: {f.get('exposure') or f.get('impact')}" for f in findings[:8]]

        # Try Gemini Generative Synthesis
        api_key = gemini_api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if api_key:
            import time
            candidate_models = ["gemini-3.5-flash", "gemini-3.5-flash-lite", "gemini-flash-lite-latest"]
            system_prompt = f"""You are an elite, highly intelligent, conversational Mobile & Web Security Architect and Reverse Engineering Assistant.
Target Application: {target_name}
Framework: {tech_info.get('primary_framework', 'Native')}
Security Score: {report.get('score_data', {}).get('score', 'N/A')}/100

Discovered Leaked Secrets & API Keys:
{json.dumps(secrets_list, indent=2)}

Live Cloud & Firebase Endpoints:
{json.dumps(cloud_diag, indent=2)}

Decompiled Code Snippets:
{json.dumps(compact_snippets, indent=2)}

Top Security Findings:
{json.dumps(findings_summary, indent=2)}

User Question: "{query}"

Instructions:
1. Act like a true intelligent, conversational AI assistant. You understand Hindi, Hinglish, and English natively. If the user asks in Hinglish (e.g. "bro ye firebase ka link bana k de" or "kya ye safe hai"), respond conversationally in natural, friendly, expert Hinglish/English.
2. If the user asks for links (such as Firebase database links, endpoints, or cloud storage URLs discovered in the scan), construct and provide the exact clickable links (e.g. `https://<db>.firebaseio.com/.json`) and explain how to verify or test them with curl.
3. If the user asks about API keys, tokens, or credentials found in the app, list them clearly with their exact values and location.
4. If the user asks about reverse engineering, payment flows, subscriptions, logic bypasses, or decompiled code, give a thorough, clear explanation with practical steps.
5. Reference specific file names and line numbers from the decompiled snippets when relevant.
6. Provide Markdown code blocks with syntax highlighting where helpful.
7. Always provide an insightful, directly actionable answer to the user's intent instead of just pasting raw code."""

            for model_name in candidate_models:
                try:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
                    payload = {
                        "contents": [{"parts": [{"text": system_prompt}]}],
                        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048}
                    }
                    r = requests.post(url, json=payload, timeout=12)
                    if r.status_code == 200:
                        resp_json = r.json()
                        candidates = resp_json.get("candidates", [])
                        if candidates:
                            text_part = candidates[0].get("content", {}).get("parts", [{}])[0].get("text")
                            if text_part:
                                return {
                                    "answer": text_part,
                                    "snippets": snippets,
                                    "scan_id": scan_id,
                                    "ai_powered": True,
                                    "model": model_name
                                }
                    elif r.status_code == 429:
                        logger.warning(f"Model {model_name} quota 429: {r.text[:80]}")
                        break
                    else:
                        logger.warning(f"Model {model_name} HTTP {r.status_code}: {r.text[:80]}")
                except Exception as e:
                    logger.debug(f"Gemini chat model {model_name} failed: {e}")

        # Heuristic Code Search & Synthesis Fallback
        return self._heuristic_code_answer(query, target_name, tech_info, snippets, findings, cloud_diag, scan_id, secrets_list)

    def _heuristic_code_answer(self, query: str, target: str, tech_info: dict, snippets: list, findings: list, cloud_diag: list, scan_id: str, secrets_list: list = None) -> Dict[str, Any]:
        """Generates a structured, conversational analysis when Gemini API experiences temporary spikes or is offline."""
        if secrets_list is None:
            secrets_list = []
            for f in findings:
                ev = f.get("evidence", {})
                sec_val = ev.get("matched_secret") or ev.get("detected_preview")
                cat = (f.get("category") or "").lower()
                tit = (f.get("title") or "").lower()
                if sec_val and ("secret" in cat or "credential" in cat or "key" in cat or "token" in tit or "secret" in tit or "key" in tit):
                    secrets_list.append({
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "file": ev.get("file"),
                        "line": ev.get("line"),
                        "secret_value": sec_val
                    })

        query_lower = query.lower()
        parts = []

        # Intent 1: Firebase / Cloud link requests
        if any(w in query_lower for w in ["firebase", "link", "database", "rtdb", "firestore", "bucket", "url", "endpoint"]):
            parts.append(f"### 🔥 Firebase & Cloud Endpoints for **{target}**\n")
            
            fb_targets = []
            for d in cloud_diag:
                url = d.get("target_url", "")
                if url:
                    fb_targets.append((d.get("service", "Cloud Endpoint"), url, d.get("verdict_badge", "AUDITED"), d.get("details", "")))
            
            found_urls = set()
            for s in snippets:
                matches = re.findall(r'https?://[a-zA-Z0-9_\-\.]+\.firebaseio\.com', s.get("content", ""))
                for m in matches:
                    found_urls.add(m)
            
            for f in findings:
                ev = f.get("evidence", {})
                txt = f"{f.get('title', '')} {f.get('impact', '')} {ev.get('context_snippet', '')} {ev.get('detected_preview', '')}"
                matches = re.findall(r'https?://[a-zA-Z0-9_\-\.]+\.firebaseio\.com', txt)
                for m in matches:
                    found_urls.add(m)

            if fb_targets or found_urls:
                parts.append("Bhai, is app ke scan aur source code se ye live Firebase URLs extract hue hain:\n")
                for svc, url, badge, det in fb_targets:
                    db_link = url if url.endswith(".json") else f"{url.rstrip('/')}/.json"
                    parts.append(f"- **{svc}:** `{url}` &bull; Status: **{badge}**")
                    parts.append(f"  - 🔗 **Direct JSON Endpoint:** [{db_link}]({db_link})")
                    if det:
                        parts.append(f"  - *Audit Note:* {det}")
                
                for u in found_urls:
                    json_url = f"{u.rstrip('/')}/.json"
                    parts.append(f"- **Realtime Database:** `{u}`")
                    parts.append(f"  - 🔗 **Direct Testing Link:** [{json_url}]({json_url})")

                parts.append("\n#### 🛠️ How to Test Public Access (Curl Command):")
                sample_url = fb_targets[0][1] if fb_targets else list(found_urls)[0]
                test_link = sample_url if sample_url.endswith(".json") else f"{sample_url.rstrip('/')}/.json"
                parts.append("```bash")
                parts.append(f'curl -s -i "{test_link}"')
                parts.append("```")
                parts.append("- **Vulnerable:** Agar response me JSON data (`{...}`) ya `null` aata hai, iska matlab database unauthenticated read ke liye publicly open hai.")
                parts.append("- **Secure:** Agar response `{\"error\": \"Permission denied\"}` aata hai, to Firebase security rules properly configure hain.\n")
            else:
                proj_name = target.replace(".", "-").replace("_", "-").lower()
                parts.append(f"Scan report me specific `.firebaseio.com` URL hardcoded nahi mila, lekin app ke package ke hisab se standard Firebase endpoints ye hote hain:\n")
                parts.append(f"- **Projected Realtime Database:** `https://{proj_name}-default-rtdb.firebaseio.com/.json`")
                parts.append(f"- **Firestore REST API:** `https://firestore.googleapis.com/v1/projects/{proj_name}/databases/(default)/documents`")
                parts.append(f"- **Cloud Storage Bucket:** `https://firebasestorage.googleapis.com/v0/b/{proj_name}.appspot.com/o`\n")

        # Intent 2: Secret / API Key Inquiries
        elif any(w in query_lower for w in ["key", "secret", "token", "password", "credential", "api_key", "kya mila", "keys"]):
            parts.append(f"### 🔑 Discovered API Keys & Secrets for **{target}**\n")
            if secrets_list:
                parts.append(f"Is app me **{len(secrets_list)}** hardcoded secrets aur credentials mile hain:\n")
                parts.append("| Type / Finding | Leaked Key Value | File Location | Line |")
                parts.append("| :--- | :--- | :--- | :--- |")
                for s in secrets_list:
                    loc = s.get('file') or 'Configuration'
                    line = s.get('line') or '-'
                    parts.append(f"| **{s.get('title')}** | `{s.get('secret_value')}` | `{loc}` | `{line}` |")
                parts.append("\n> ⚠️ **Security Risk:** Hardcoded API keys ko koi bhi APK decompile karke extract kar sakta hai. Sensitive APIs ko backend proxy ke peeche rakhein aur Cloud Console par key restrictions lagayein.\n")
            else:
                parts.append("Is audit me koi critical hardcoded API keys ya secrets flag nahi hue hain.\n")

        # Intent 3: Billing / Subscription / In-App Purchases
        elif any(w in query_lower for w in ["billing", "subscription", "payment", "bypass", "purchase", "premium", "pro"]):
            parts.append(f"### 💳 In-App Billing & Subscription Security Analysis for **{target}**\n")
            parts.append("#### 1. Architecture Overview:")
            parts.append("Android applications Google Play Billing Library (`BillingClient`) use karti hain premium features aur subscriptions unlock karne ke liye.")
            parts.append("- **Client-Side Flow:** App `BillingClient.queryPurchasesAsync()` ya `PurchasesUpdatedListener` use karke purchase state check karti hai.")
            parts.append("- **Vulnerability Vector:** Agar app sirf client-side boolean check (`isPremium = true` ya `purchase.getPurchaseState() == 1`) par depend karti hai bina server validation ke, to use easily bypass kiya ja sakta hai.\n")
            parts.append("#### 2. Reverse Engineering / Bypass Points:")
            parts.append("1. **Frida Dynamic Hooking:** Runtime par `BillingClient` ke `queryPurchasesAsync` callback ya entitlement methods ko hook karke `PURCHASED` state inject karna.")
            parts.append("2. **Smali Bytecode Patching:** `classes.dex` me check method ko `const/4 v0, 0x1; return v0` se replace karke APK resign karna.\n")
            parts.append("#### 3. Secure Remediation:")
            parts.append("- **Always Verify on Server:** Client-side tokens par kabhi trust na karein. `purchaseToken` ko apne backend server par bhejein aur Google Play Developer API (`purchases.subscriptionsv2.get`) se backend-to-backend verify karein.\n")

        # Intent 4: General / Conversational fallback
        else:
            parts.append(f"### 🛡️ Security Audit Analysis for **{target}**")
            parts.append(f"**Question:** *\"{query}\"*\n")
            parts.append(f"- **Primary Framework:** `{tech_info.get('primary_framework', 'Native Android')}`")
            parts.append(f"- **Total Security Findings:** {len(findings)} issues identified.\n")

        # Relevant snippets if any matched
        if snippets:
            parts.append(f"#### 📂 Relevant Decompiled Source Snippets ({len(snippets)} matched):")
            for idx, snip in enumerate(snippets[:3], 1):
                parts.append(f"**{idx}. File: `{snip['file']}` (Lines {snip['line_start']}-{snip['line_end']})**")
                parts.append(f"```java\n{snip['content'].strip()}\n```\n")

        parts.append("> 💡 *Note: Google Gemini Flash experienced high API demand spikes; synthesized using Decryptor Deep Security Engine.*")

        return {
            "answer": "\n".join(parts),
            "snippets": snippets,
            "scan_id": scan_id,
            "ai_powered": False
        }
