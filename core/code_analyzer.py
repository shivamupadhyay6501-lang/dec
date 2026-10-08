import os
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger("scanner.code_analyzer")

class CodeAnalyzer:
    """
    Audits decompiled Java, Kotlin, and JavaScript code for code-level security anti-patterns:
    Insecure WebViews, weak crypto, disabled TLS validation, insecure storage, and logging of sensitive data.
    """

    CODE_RULES = [
        # --- 🔴 CRITICAL / 🟠 HIGH VULNERABILITIES ---
        {
            "id": "CODE-TLS-001",
            "name": "TLS Certificate Validation Disabled (TrustAllCerts)",
            "pattern": r"(?s)(?:checkServerTrusted|checkClientTrusted)\s*\([^\)]*\)\s*\{(?:\s*//[^\n]*|\s*)\}",
            "severity": "CRITICAL",
            "category": "Network & TLS Security",
            "confidence": 0.98,
            "impact": "The app accepts any SSL/TLS certificate unconditionally, enabling trivial Man-in-the-Middle (MITM) attacks to decrypt all API traffic.",
            "remediation": "Remove empty TrustManager implementations and use Android's default system trust store or Network Security Config."
        },
        {
            "id": "CODE-TLS-002",
            "name": "Hostname Verification Disabled (AllowAllHostnameVerifier)",
            "pattern": r"(?i)(?:ALLOW_ALL_HOSTNAME_VERIFIER|verify\s*\([^\)]*\)\s*\{\s*return\s+true\s*;\s*\})",
            "severity": "CRITICAL",
            "category": "Network & TLS Security",
            "confidence": 0.96,
            "impact": "Disables SSL hostname validation. An attacker with a certificate for any valid domain can impersonate your backend API.",
            "remediation": "Do not override `HostnameVerifier` to return `true`. Let OkHttp or standard HttpsURLConnection enforce hostname matching."
        },
        {
            "id": "CODE-WEBVIEW-001",
            "name": "WebView Ignores SSL Errors (handler.proceed())",
            "pattern": r"onReceivedSslError\s*\([^\)]*\)\s*\{[^}]*handler\.proceed\(\)",
            "severity": "CRITICAL",
            "category": "WebView Security",
            "confidence": 0.99,
            "impact": "Forces the WebView to load pages with invalid, expired, or self-signed SSL certificates, opening users to phishing and credential theft.",
            "remediation": "Remove `handler.proceed()` from `onReceivedSslError`. Call `handler.cancel()` to abort connection on SSL errors."
        },
        {
            "id": "CODE-WEBVIEW-002",
            "name": "Insecure WebView Universal File Access Enabled",
            "pattern": r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",
            "severity": "HIGH",
            "category": "WebView Security",
            "confidence": 0.98,
            "impact": "Permits JavaScript running in a file scheme context to access any file in the app private data directory (Cross-Origin File Theft).",
            "remediation": "Set `setAllowUniversalAccessFromFileURLs(false)` and `setAllowFileAccessFromFileURLs(false)`."
        },
        {
            "id": "CODE-CRYPTO-001",
            "name": "Weak / Broken Encryption Algorithm (DES / 3DES / RC4)",
            "pattern": r"Cipher\.getInstance\s*\(\s*[\"'](?:DES|DESede|RC4|Blowfish)[\"'/]",
            "severity": "HIGH",
            "category": "Cryptographic Weakness",
            "confidence": 0.99,
            "impact": "Using deprecated and computationally breakable encryption algorithms allows attackers to decrypt encrypted data.",
            "remediation": "Upgrade to AES-256 in GCM mode (`AES/GCM/NoPadding`) with a 256-bit key stored in the Android Keystore."
        },
        {
            "id": "CODE-CRYPTO-002",
            "name": "Insecure AES ECB Mode (Electronic Codebook)",
            "pattern": r"Cipher\.getInstance\s*\(\s*[\"']AES/ECB/",
            "severity": "HIGH",
            "category": "Cryptographic Weakness",
            "confidence": 0.99,
            "impact": "ECB mode does not use an Initialization Vector (IV). Identical plaintext blocks produce identical ciphertext blocks, leaking data patterns.",
            "remediation": "Use `AES/GCM/NoPadding` or `AES/CBC/PKCS7Padding` with a cryptographically secure random IV (`SecureRandom`)."
        },
        {
            "id": "CODE-STORAGE-001",
            "name": "World Readable / Writable File Storage Mode",
            "pattern": r"(?:MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)",
            "severity": "HIGH",
            "category": "Insecure Data Storage",
            "confidence": 0.99,
            "impact": "Creates files that can be read or overwritten by any other third-party application installed on the user device.",
            "remediation": "Use `Context.MODE_PRIVATE` and migrate to `EncryptedSharedPreferences` / `EncryptedFile` from the Jetpack Security library."
        },

        {
            "id": "CODE-INTENT-001",
            "name": "Insecure Mutable PendingIntent Flag (CVE-2021-0306 / Intent Hijacking)",
            "pattern": r"PendingIntent\.(?:getActivity|getBroadcast|getService)\s*\([^)]*FLAG_MUTABLE",
            "severity": "HIGH",
            "category": "Inter-Process Communication (IPC)",
            "confidence": 0.95,
            "impact": "A mutable PendingIntent allows external third-party apps on the device to intercept or modify intent extras and action parameters, leading to privilege escalation.",
            "remediation": "Use `PendingIntent.FLAG_IMMUTABLE` unless intent mutation is strictly required. If mutation is needed, explicitly set the target component name on the base intent."
        },
        {
            "id": "CODE-CRYPTO-004",
            "name": "Hardcoded Symmetric Cryptographic Key / IV",
            "pattern": r"new\s+SecretKeySpec\s*\(\s*[\"'][^\"']+[\"']\.getBytes\(\)",
            "severity": "HIGH",
            "category": "Cryptographic Weakness",
            "confidence": 0.98,
            "impact": "Static symmetric encryption keys embedded in the binary allow trivial decryption of protected data or tokens across all app instances.",
            "remediation": "Generate unique encryption keys at runtime and store them securely inside the hardware-backed Android Keystore."
        },
        {
            "id": "CODE-RANDOM-001",
            "name": "Insecure Random Number Generator for Security Operations",
            "pattern": r"new\s+java\.util\.Random\s*\(",
            "severity": "MEDIUM",
            "category": "Cryptographic Weakness",
            "confidence": 0.90,
            "impact": "`java.util.Random` produces predictable pseudorandom sequences. An attacker can predict session tokens, nonces, or reset codes.",
            "remediation": "Replace `java.util.Random` with `java.security.SecureRandom`."
        },

        # --- 🟡 MEDIUM / 🔵 LOW VULNERABILITIES ---
        {
            "id": "CODE-CRYPTO-003",
            "name": "Weak Cryptographic Hash (MD5 / SHA-1)",
            "pattern": r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1|SHA1)[\"']\s*\)",
            "severity": "MEDIUM",
            "category": "Cryptographic Weakness",
            "confidence": 0.90,
            "impact": "MD5 and SHA-1 suffer from known collision vulnerabilities and should not be used for security-critical signing or password hashing.",
            "remediation": "Use SHA-256, SHA-512, or bcrypt/Argon2 for password hashing."
        },
        {
            "id": "CODE-NET-001",
            "name": "Hardcoded Internal / Staging Server URL",
            "pattern": r"https?://(?:staging\.|test\.|dev\.|internal\.|qa\.|uat\.)[a-zA-Z0-9_\-\.]+",
            "severity": "MEDIUM",
            "category": "Information Disclosure",
            "confidence": 0.85,
            "impact": "Exposes internal pre-production testing or staging infrastructure to public inspection, which often runs with weaker security controls.",
            "remediation": "Use build variant configuration (`buildConfigField`) to strip staging endpoints from release builds."
        },
        {
            "id": "CODE-LOG-001",
            "name": "Production Logging of Sensitive Parameters",
            "pattern": r"Log\.[dev]\s*\([^,]+,\s*(?:[^\)]*(?:password|token|secret|bearer|authorization|credit_card|cvv))[^\)]*\)",
            "severity": "LOW",
            "category": "Data Leakage",
            "confidence": 0.80,
            "impact": "Writes sensitive authentication tokens or user credentials to logcat, which can be read by device logs or crash monitoring tools.",
            "remediation": "Disable non-critical logs in release builds using ProGuard/R8 rules or Timber trees."
        }
    ]

    def scan_directory(self, sources_dir: str) -> List[Dict[str, Any]]:
        """
        Scans all decompiled Java, Kotlin, and JavaScript source files for code vulnerabilities.
        """
        if not sources_dir or not os.path.exists(sources_dir):
            return []

        findings = []
        scannable_exts = {".java", ".kt", ".js", ".ts"}

        for root, _, files in os.walk(sources_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in scannable_exts:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, sources_dir).replace("\\", "/")

                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        lines = content.split("\n")

                        for rule in self.CODE_RULES:
                            matches = list(re.finditer(rule["pattern"], content))
                            for match in matches:
                                line_no = content[:match.start()].count("\n") + 1
                                start_idx = max(0, line_no - 3)
                                end_idx = min(len(lines), line_no + 2)
                                context_snippet = "\n".join(lines[start_idx:end_idx])

                                findings.append({
                                    "id": rule["id"],
                                    "category": rule["category"],
                                    "title": rule["name"],
                                    "severity": rule["severity"],
                                    "confidence": rule["confidence"],
                                    "exposure": "Decompiled client bytecode logic",
                                    "evidence": {
                                        "file": rel_path,
                                        "line": line_no,
                                        "context_snippet": context_snippet
                                    },
                                    "impact": rule["impact"],
                                    "remediation": rule["remediation"]
                                })
                    except Exception as e:
                        logger.debug(f"Error analyzing code file {full_path}: {e}")

        return findings
