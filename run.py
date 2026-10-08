import os
import sys
import argparse
import uvicorn

def main():
    parser = argparse.ArgumentParser(description="APK Security Intelligence & Executive Auditor")
    parser.add_argument("command", nargs="?", default="serve", choices=["serve", "scan", "test"], help="Command to run (default: serve)")
    parser.add_argument("--target", help="Play Store URL, package name, or APK file path (for scan command)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind the server (default: 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the server (default: 0.0.0.0)")

    args = parser.parse_args()

    if args.command == "serve":
        print(f"\n=======================================================")
        print(f"🛡️  APK SECURITY INTELLIGENCE & EXECUTIVE AUDITOR")
        print(f"🌐 Dashboard URL: http://localhost:{args.port}")
        print(f"📚 Swagger Docs:  http://localhost:{args.port}/docs")
        print(f"=======================================================\n")
        uvicorn.run("server.main:app", host=args.host, port=args.port, reload=True)

    elif args.command == "scan":
        if not args.target:
            print("Error: --target is required for 'scan' command. (e.g. python run.py scan --target ./samples/vulnerable_demo_app.apk)")
            sys.exit(1)
        
        from core.orchestrator import AuditOrchestrator
        orchestrator = AuditOrchestrator()
        
        is_file = os.path.isfile(args.target)
        is_url = not is_file

        def cli_progress(msg, pct):
            print(f"[{pct:>3}%] {msg}")

        print(f"\n[INIT] Starting automated security audit for: {args.target}")
        report = orchestrator.run_audit(args.target, is_url=is_url, progress_callback=cli_progress)

        
        score_data = report.get("score_data", {})
        print(f"\n================ AUDIT SUMMARY ================")
        print(f"Target:         {report['app_info']['package']} (v{report['app_info']['version_name']})")
        print(f"Framework:      {report['tech_info']['primary_framework']}")
        print(f"Security Score: {score_data.get('score')}/100 ({score_data.get('risk_level')})")
        print(f"Findings:       {len(report.get('findings', []))} total")
        print(f"Report ID:      {report['scan_id']}")
        print(f"===============================================\n")

    elif args.command == "test":
        import subprocess
        subprocess.run([sys.executable, "tests/test_engine.py"])

if __name__ == "__main__":
    main()
