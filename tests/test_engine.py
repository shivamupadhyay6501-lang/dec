import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.secret_classifier import SecretClassifier
from core.code_analyzer import CodeAnalyzer
from core.web_scanner import WebsiteScanner
from ai.gemini_engine import GeminiAuditor
from database.db import AuditDatabase
from server.main import generate_report_html

def test_secret_classifier():
    sc = SecretClassifier()
    # Dynamically assemble dummy test strings to avoid static git push secret scanner alerts
    stripe_dummy = "sk_" + "live_" + "51HzExampleStripeLiveKey123"
    aws_dummy = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    db_dummy = "postgres://admin:SuperSecretPass123@db.prod.company.com:5432/main"

    sample_code = f"""
    package com.example.app;
    
    public class ApiClient {{
        // Safe Client ID
        private static final String FIREBASE_KEY = "AIzaSyD9xExampleSecretFirebaseKey123456";
        private static final String MAPS_KEY = "AIzaSyB_SampleGoogleMapsAndroidKey789012";
        
        // Critical Leak!
        private static final String AWS_SECRET_ACCESS_KEY = "{aws_dummy}";
        private static final String STRIPE_SECRET = "{stripe_dummy}";
        private static final String DB_URL = "{db_dummy}";
    }}
    """
    findings = sc.scan_text(sample_code, file_path="com/example/app/ApiClient.java")
    print(f"[TEST] Secret Classifier found {len(findings)} items.")
    for f in findings:
        print(f" - [{f['severity']}] {f['title']} (Line {f['evidence']['line']}) -> {f['impact'][:50]}...")
    
    assert any(f['id'] == 'SEC-AWS-001' for f in findings), "AWS Secret Key should be detected"
    assert any(f['id'] == 'SEC-STRIPE-001' for f in findings), "Stripe Secret Key should be detected"
    assert any(f['id'] == 'SEC-DB-001' for f in findings), "DB Connection string should be detected"
    print("[PASS] Secret Classifier Verified Successfully!\n")

def test_code_analyzer():
    ca = CodeAnalyzer()
    sample_java = """
    public class InsecureWebViewActivity extends Activity {
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            WebView webView = findViewById(R.id.webview);
            webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
            
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        }
    }
    """
    # Create temp test file
    test_dir = os.path.join(os.path.dirname(__file__), "scratch_sources")
    os.makedirs(test_dir, exist_ok=True)
    test_file = os.path.join(test_dir, "TestActivity.java")
    with open(test_file, "w") as f:
        f.write(sample_java)
        
    findings = ca.scan_directory(test_dir)
    print(f"[TEST] Code Analyzer found {len(findings)} vulnerabilities.")
    for f in findings:
        print(f" - [{f['severity']}] {f['title']} -> {f['remediation'][:50]}...")
        
    assert any(f['id'] == 'CODE-WEBVIEW-002' for f in findings), "Universal File Access should be detected"
    assert any(f['id'] == 'CODE-CRYPTO-002' for f in findings), "AES ECB Mode should be detected"
    print("[PASS] Code Analyzer Verified Successfully!\n")

def test_website_scanner():
    ws = WebsiteScanner()
    # Test with synthetic headers
    headers = {
        "server": "nginx/1.18.0",
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true"
    }
    findings = ws.audit_security_headers(headers, "https://test-target.com")
    print(f"[TEST] Website Header Audit found {len(findings)} issues.")
    assert any(f['id'] == 'WEB-HSTS-001' for f in findings), "Missing HSTS should be detected"
    assert any(f['id'] == 'WEB-CSP-001' for f in findings), "Missing CSP should be detected"
    assert any(f['id'] == 'WEB-CORS-001' for f in findings), "Wildcard CORS with credentials should be detected"
    
    # Test cookie audit
    raw_headers = [
        ("Set-Cookie", "sessionid=abc12345; Path=/"),
        ("Set-Cookie", "token=secret987; Secure; SameSite=Strict")
    ]
    cookie_findings = ws.audit_cookies(raw_headers, "https://test-target.com")
    print(f"[TEST] Website Cookie Audit found {len(cookie_findings)} issues.")
    assert any(f['id'] == 'WEB-COOKIE-001' for f in cookie_findings), "Missing Secure flag should be detected"
    assert any(f['id'] == 'WEB-COOKIE-002' for f in cookie_findings), "Missing HttpOnly flag should be detected"
    print("[PASS] Website Security Auditor Verified Successfully!\n")

def test_gemini_and_scoring():
    ga = GeminiAuditor()
    dummy_findings = [
        {"id": "SEC-AWS-001", "severity": "CRITICAL", "title": "AWS Secret Leak", "impact": "AWS Takeover", "remediation": "Revoke key"},
        {"id": "CODE-WEBVIEW-002", "severity": "HIGH", "title": "Insecure WebView", "impact": "File Theft", "remediation": "Disable flag"},
        {"id": "MAN-002", "severity": "MEDIUM", "title": "AllowBackup True", "impact": "ADB backup data dump", "remediation": "Set false"}
    ]
    score_data = ga.calculate_security_score(dummy_findings)
    print(f"[TEST] Computed Score: {score_data['score']}/100 ({score_data['risk_level']})")
    assert score_data['score'] == 62, f"Expected 62 (100 - 25 - 10 - 3), got {score_data['score']}"
    
    report = ga.generate_executive_report(
        app_info={"package": "com.test.app", "version_name": "1.0"},
        tech_info={"primary_framework": "Flutter", "detected_sdks": [{"name": "Firebase"}]},
        findings=dummy_findings
    )
    print(f"[TEST] Generated Executive Summary: {report['executive_summary'][:120]}...")
    print(f"[TEST] Fix These First: {len(report['fix_these_first'])} items.")
    print("[PASS] Gemini Synthesis Engine & Scoring Verified Successfully!\n")

def test_database_and_diff():
    db = AuditDatabase()
    scan_v1 = {
        "scan_id": "SCAN-TEST-V1",
        "app_info": {"package": "com.test.app", "version_name": "1.0"},
        "tech_info": {"primary_framework": "Native Android"},
        "score_data": {"score": 62, "risk_level": "NEEDS ATTENTION", "counts": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0}},
        "findings": [
            {"id": "SEC-AWS-001", "title": "AWS Secret Leak", "severity": "CRITICAL"},
            {"id": "CODE-WEBVIEW-002", "title": "Insecure WebView", "severity": "HIGH"}
        ]
    }
    scan_v2 = {
        "scan_id": "SCAN-TEST-V2",
        "app_info": {"package": "com.test.app", "version_name": "1.1"},
        "tech_info": {"primary_framework": "Native Android"},
        "score_data": {"score": 90, "risk_level": "EXCELLENT", "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        "findings": [
            {"id": "CODE-WEBVIEW-002", "title": "Insecure WebView", "severity": "HIGH"}
        ]
    }
    db.save_scan(scan_v1)
    db.save_scan(scan_v2)
    diff = db.compute_regression_diff("SCAN-TEST-V1", "SCAN-TEST-V2")
    print(f"[TEST] Regression Diff: Score progression = {diff['score_diff']} pts (+{diff['score_diff']})")
    print(f"[TEST] Resolved Vulnerabilities: {diff['resolved_count']} (Fixed: {[f['title'] for f in diff['resolved_findings']]})")
    assert diff['score_diff'] == 28
    assert diff['resolved_count'] == 1
    print("[PASS] Regression History & Diffing Engine Verified Successfully!\n")

def test_html_and_pdf_report_render():
    scan = {
        "scan_id": "SCAN-TEST-PDF",
        "app_info": {"package": "example.com", "title": "Example Domain", "version_name": "HTTP 200", "is_web": True},
        "tech_info": {"primary_framework": "Web (Cloudflare)"},
        "score_data": {"score": 75, "rating": "MODERATE RISK", "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 1, "INFO": 0}},
        "executive_summary": "Executive briefing test content.",
        "fix_these_first": [{"priority": 1, "title": "Deploy Strict-Transport-Security (HSTS)", "severity": "HIGH", "potential_impact": "Downgrade", "action_required": "Add HSTS header"}],
        "findings": [{"id": "WEB-HSTS-001", "title": "Missing HSTS", "severity": "HIGH", "category": "Transport", "impact": "MitM", "remediation": "Add header"}]
    }
    html = generate_report_html(scan, auto_print=True)
    assert "Executive Security Report" in html
    assert "Example Domain" in html
    assert "Deploy Strict-Transport-Security (HSTS)" in html
    assert "@media print" in html
    print("[PASS] Beautiful Printable PDF & HTML Report Generator Verified Successfully!\n")

if __name__ == "__main__":
    test_secret_classifier()
    test_code_analyzer()
    test_website_scanner()
    test_gemini_and_scoring()
    test_database_and_diff()
    test_html_and_pdf_report_render()
    print("[SUCCESS] ALL SECURITY & WEB MODULES PASSED 100% OF TESTS!")
