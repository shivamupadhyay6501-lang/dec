import os
import re
import math
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("scanner.secret_classifier")

class SecretClassifier:
    """
    Scans code, strings, and resources for hardcoded secrets, credentials, and API keys.
    Distinguishes between genuine critical secrets and public client identifiers.
    """

    SECRET_RULES = [
        # --- 🔴 CRITICAL SECRETS ---
        {
            "id": "SEC-AWS-001",
            "name": "AWS Secret Access Key",
            "pattern": r"(?i)(?:aws_secret_access_key|aws_secret|aws_key|secret_key)\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']",
            "severity": "CRITICAL",
            "category": "Cloud Infrastructure Credential",
            "confidence": 0.95,
            "impact": "Grants direct API access to AWS cloud infrastructure, EC2 instances, S3 storage, or databases.",
            "remediation": "Immediately revoke and rotate the AWS IAM access key in AWS IAM Console. Delegate privileged operations to your backend API."
        },
        {
            "id": "SEC-AWS-002",
            "name": "AWS Access Key ID with Embedded Secret",
            "pattern": r"(A3T[A-Z0-9]|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})",
            "severity": "HIGH",
            "category": "Cloud Infrastructure Credential",
            "confidence": 0.90,
            "impact": "Exposes an AWS IAM Access Key ID. If paired with an embedded secret or default permissions, attackers can query AWS services.",
            "remediation": "Audit IAM permissions associated with this Access Key ID and ensure it is not hardcoded in the client binary."
        },
        {
            "id": "SEC-GCP-001",
            "name": "Google Cloud / Firebase Service Account Private Key",
            "pattern": r"\"type\"\s*:\s*\"service_account\"[\s\S]{1,100}\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----",
            "severity": "CRITICAL",
            "category": "Cloud Infrastructure Credential",
            "confidence": 0.99,
            "impact": "Grants complete administrative control over Google Cloud Platform services, Firebase databases, and storage buckets.",
            "remediation": "Delete this service account key in GCP IAM Console immediately and rotate all associated credentials."
        },
        {
            "id": "SEC-STRIPE-001",
            "name": "Stripe Live Secret Key",
            "pattern": r"sk_live_[0-9a-zA-Z]{24,34}",
            "severity": "CRITICAL",
            "category": "Payment Gateway Credential",
            "confidence": 0.99,
            "impact": "Permits unauthorized charges, refunds, customer balance modification, and banking data retrieval via the Stripe API.",
            "remediation": "Roll this secret key in the Stripe Dashboard immediately and restrict live operations to your backend."
        },
        {
            "id": "SEC-SUPABASE-001",
            "name": "Supabase Service Role Secret Key",
            "pattern": r"(?i)supabase.*(?:service_role|service_key)\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{50,})[\"']",
            "severity": "CRITICAL",
            "category": "Database Superuser Key",
            "confidence": 0.98,
            "impact": "Bypasses Row Level Security (RLS) policies and provides full administrative read/write access to the Supabase database.",
            "remediation": "Replace with the public `anon` key in client code. Keep the `service_role` key strictly on your secure server."
        },
        {
            "id": "SEC-DB-001",
            "name": "Hardcoded Database Connection String",
            "pattern": r"(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_\.\-]+:[a-zA-Z0-9_\.\-@%]+@[a-zA-Z0-9_\.\-]+",
            "severity": "CRITICAL",
            "category": "Direct Database Access",
            "confidence": 0.96,
            "impact": "Exposes raw database host, username, and password. Allows direct SQL injection, database dump, or ransomware extortion.",
            "remediation": "Never connect directly to a database from a mobile client. Route all database queries through an authenticated REST/GraphQL API."
        },
        {
            "id": "SEC-KEY-001",
            "name": "Hardcoded RSA/EC/PGP Private Key",
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "severity": "CRITICAL",
            "category": "Cryptographic Key Leak",
            "confidence": 1.0,
            "impact": "Permits decryption of private communications, token forgery, or server impersonation.",
            "remediation": "Remove the private key from the APK assets and store cryptographic keys in the Android Keystore or on the server."
        },
        {
            "id": "SEC-AI-001",
            "name": "OpenAI / Anthropic Secret API Key",
            "pattern": r"(sk-[a-zA-Z0-9]{48}|sk-ant-api[0-9]{2}-[a-zA-Z0-9_\-]{80,})",
            "severity": "HIGH",
            "category": "AI Provider Credential",
            "confidence": 0.95,
            "impact": "Allows attackers to drain your AI API quota, run unauthorized models, or access stored assistant conversations.",
            "remediation": "Revoke the key on platform.openai.com or console.anthropic.com and proxy LLM calls through your backend."
        },
        {
            "id": "SEC-SLACK-001",
            "name": "Slack Bot / User Access Token",
            "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}",
            "severity": "HIGH",
            "category": "Internal Communication Token",
            "confidence": 0.98,
            "impact": "Allows attackers to read internal workspace messages, upload files, or impersonate team members.",
            "remediation": "Revoke token on api.slack.com and regenerate."
        },
        {
            "id": "SEC-GITHUB-001",
            "name": "GitHub Personal Access Token",
            "pattern": r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})",
            "severity": "HIGH",
            "category": "Source Code Access Token",
            "confidence": 0.98,
            "impact": "Allows unauthorized access to private GitHub repositories, release artifacts, and CI/CD pipelines.",
            "remediation": "Revoke the token immediately on github.com/settings/tokens."
        },
        {
            "id": "SEC-SENDGRID-001",
            "name": "SendGrid / Mailgun API Key",
            "pattern": r"(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}|key-[0-9a-zA-Z]{32})",
            "severity": "HIGH",
            "category": "Email Service Credential",
            "confidence": 0.92,
            "impact": "Permits unauthorized bulk email sending, spam campaigns, or phishing under your verified domain.",
            "remediation": "Rotate API key in SendGrid / Mailgun settings."
        },

        # --- 🔵 PUBLIC / CLIENT-SIDE IDENTIFIERS (LOW / INFO - SAFE CONTEXT) ---
        {
            "id": "PUB-GOOGLE-001",
            "name": "Google API / Firebase Web Key",
            "pattern": r"AIza[0-9A-Za-z_\-]{35}",
            "severity": "INFO",
            "category": "Client Public Identifier",
            "confidence": 0.90,
            "impact": "Standard Google client-side API key. By design, this key is embedded in Android apps to identify Firebase/Maps projects.",
            "remediation": "Ensure this key is restricted by Android package name and SHA-1 fingerprint in the Google Cloud Console."
        },
        {
            "id": "PUB-STRIPE-001",
            "name": "Stripe Publishable Key",
            "pattern": r"pk_live_[0-9a-zA-Z]{24,34}",
            "severity": "INFO",
            "category": "Payment Client Token",
            "confidence": 0.95,
            "impact": "Client-side publishable key used for tokenizing credit cards on the device. It has no access to customer account data.",
            "remediation": "No immediate action required. This is standard client-side implementation."
        },
        {
            "id": "PUB-SUPABASE-001",
            "name": "Supabase Public Anon Key",
            "pattern": r"(?i)supabase.*(?:anon_key|public_key)\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{50,})[\"']",
            "severity": "INFO",
            "category": "BaaS Public Client Key",
            "confidence": 0.90,
            "impact": "Standard Supabase client key. Access is controlled via PostgreSQL Row Level Security (RLS) policies on your tables.",
            "remediation": "Verify that Row Level Security (RLS) is enabled on all sensitive Supabase tables."
        },
        {
            "id": "PUB-SENTRY-001",
            "name": "Sentry / Bugsnag DSN",
            "pattern": r"https://[a-f0-9]{32}@[a-z0-9\.\-]+\/[0-9]+",
            "severity": "INFO",
            "category": "Observability DSN",
            "confidence": 0.95,
            "impact": "Public DSN used for submitting crash logs to Sentry.",
            "remediation": "No action required. DSNs are designed to be public."
        }
    ]

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    def scan_text(self, text: str, file_path: str = "Unknown") -> List[Dict[str, Any]]:
        """
        Scans a text file or string for secret patterns and high entropy tokens.
        """
        findings = []
        lines = text.split("\n")

        for rule in self.SECRET_RULES:
            matches = list(re.finditer(rule["pattern"], text))
            for match in matches:
                # Calculate line number
                start_pos = match.start()
                line_no = text[:start_pos].count("\n") + 1
                matched_val = match.group(0)

                # Obfuscate secret in evidence preview
                if len(matched_val) > 8 and rule["severity"] in ["CRITICAL", "HIGH"]:
                    preview = matched_val[:4] + "..." + matched_val[-4:]
                else:
                    preview = matched_val

                # Get context snippet (2 lines before and after)
                start_line_idx = max(0, line_no - 3)
                end_line_idx = min(len(lines), line_no + 2)
                context_snippet = "\n".join(lines[start_line_idx:end_line_idx])

                findings.append({
                    "id": rule["id"],
                    "category": rule["category"],
                    "title": rule["name"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "exposure": "Publicly recoverable from decompiled code / assets",
                    "evidence": {
                        "file": file_path,
                        "line": line_no,
                        "detected_preview": preview,
                        "context_snippet": context_snippet,
                        "entropy": self.calculate_shannon_entropy(matched_val)
                    },
                    "impact": rule["impact"],
                    "remediation": rule["remediation"]
                })

        return findings

    def scan_directory(self, base_dir: str, max_file_size_mb: float = 5.0) -> List[Dict[str, Any]]:
        """
        Recursively scans all decompiled source files, assets, and configs.
        """
        all_findings = []
        scannable_exts = {
            ".java", ".kt", ".xml", ".json", ".js", ".bundle",
            ".ts", ".dart", ".properties", ".env", ".txt", ".yaml", ".yml"
        }

        for root, _, files in os.walk(base_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in scannable_exts or file in ["AndroidManifest.xml", "index.android.bundle"]:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, base_dir).replace("\\", "/")

                    try:
                        size_mb = os.path.getsize(full_path) / (1024 * 1024)
                        if size_mb > max_file_size_mb:
                            continue

                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        findings = self.scan_text(content, file_path=rel_path)
                        all_findings.extend(findings)
                    except Exception as e:
                        logger.debug(f"Error scanning {full_path}: {e}")

        return all_findings
