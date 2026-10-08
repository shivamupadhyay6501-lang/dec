import os
import json
import logging
from typing import Dict, Any, List, Optional
try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None

logger = logging.getLogger("scanner.gemini_engine")

class GeminiAuditor:
    """
    Synthesizes machine-extracted static analysis evidence into an authoritative
    Executive Security Report with developer-ready remediation guidance.
    """

    def __init__(self, api_key: Optional[str] = None):
        # Auto-load from .env if present
        if not api_key and not os.environ.get("GEMINI_API_KEY"):
            env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
            if os.path.exists(env_file):
                try:
                    with open(env_file, "r") as f:
                        for line in f:
                            if line.startswith("GEMINI_API_KEY="):
                                os.environ["GEMINI_API_KEY"] = line.strip().split("=", 1)[1]
                            elif line.startswith("GOOGLE_API_KEY="):
                                os.environ["GOOGLE_API_KEY"] = line.strip().split("=", 1)[1]
                except Exception as e:
                    logger.debug(f"Error reading .env: {e}")

        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.client = None
        if self.api_key and genai:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")

    @staticmethod
    def calculate_security_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Computes the deterministic security posture score (0 - 100).
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1

        # Penalty deductions
        deductions = (
            counts["CRITICAL"] * 25 +
            counts["HIGH"] * 10 +
            counts["MEDIUM"] * 3 +
            counts["LOW"] * 1
        )
        score = max(0, min(100, 100 - deductions))

        if score >= 90:
            rating = "EXCELLENT"
            risk_level = "LOW RISK"
        elif score >= 75:
            rating = "GOOD"
            risk_level = "MODERATE RISK"
        elif score >= 50:
            rating = "NEEDS ATTENTION"
            risk_level = "HIGH RISK"
        else:
            rating = "CRITICAL ACTION REQUIRED"
            risk_level = "SEVERE RISK"

        return {
            "score": score,
            "rating": rating,
            "risk_level": risk_level,
            "counts": counts
        }

    def generate_executive_report(self, app_info: Dict[str, Any], tech_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generates executive narrative and top remediation priorities using Gemini Flash.
        Falls back to rule-based synthesis if API key is not present.
        """
        score_data = self.calculate_security_score(findings)

        # Separate critical/high from others
        critical_high = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
        
        # If Gemini client is active, request LLM synthesis
        if self.client:
            try:
                return self._call_gemini_synthesis(app_info, tech_info, findings, score_data, critical_high)
            except Exception as e:
                logger.error(f"Gemini API call failed: {e}. Falling back to heuristic synthesizer.")

        return self._local_heuristic_synthesis(app_info, tech_info, findings, score_data, critical_high)

    def _call_gemini_synthesis(self, app_info, tech_info, findings, score_data, critical_high) -> Dict[str, Any]:
        """Calls Gemini Flash API with compact evidence payload."""
        prompt_payload = {
            "application": app_info,
            "technology_stack": tech_info,
            "security_score": score_data,
            "top_findings": critical_high[:10]  # compact representation to save tokens
        }

        system_instruction = """
You are a Principal Mobile Security Architect and CISO Advisor.
You will be provided with structured machine evidence extracted from a decompiled Android APK.
Analyze the findings and provide a crisp, authoritative executive security evaluation.

Return ONLY valid JSON matching this schema:
{
  "executive_summary": "2-3 paragraphs summarizing overall posture, attack surface exposure, and business risk.",
  "fix_these_first": [
    {
      "priority": 1,
      "title": "Clear concise vulnerability title",
      "severity": "CRITICAL/HIGH",
      "potential_impact": "Direct business & data exposure consequence",
      "action_required": "Exact immediate step the engineering team must take"
    }
  ],
  "architectural_recommendations": [
    "Key engineering practice or architectural improvement"
  ]
}
"""

        candidate_models = ["gemini-flash-latest", "gemini-2.5-flash-lite", "gemini-3-flash-preview", "gemini-pro-latest"]
        last_err = None
        for model_name in candidate_models:
            try:
                response = self.client.models.generate_content(
                    model=model_name,
                    contents=f"System Evidence Payload:\n```json\n{json.dumps(prompt_payload, indent=2)}\n```",
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        response_mime_type="application/json",
                        temperature=0.2
                    )
                )

                raw_text = response.text.strip()
                if raw_text.startswith("```json"):
                    raw_text = raw_text[7:]
                if raw_text.startswith("```"):
                    raw_text = raw_text[3:]
                if raw_text.endswith("```"):
                    raw_text = raw_text[:-3]

                ai_data = json.loads(raw_text.strip())
                return {
                    "score_data": score_data,
                    "executive_summary": ai_data.get("executive_summary", ""),
                    "fix_these_first": ai_data.get("fix_these_first", []),
                    "architectural_recommendations": ai_data.get("architectural_recommendations", []),
                    "generated_by": f"Gemini AI ({model_name})"
                }
            except Exception as err:
                last_err = err
                logger.debug(f"Model {model_name} failed: {err}")

        raise last_err or RuntimeError("All candidate Gemini models failed")

    def _local_heuristic_synthesis(self, app_info, tech_info, findings, score_data, critical_high) -> Dict[str, Any]:
        """Deterministic fallback synthesizer when offline or API key is absent."""
        counts = score_data["counts"]
        score = score_data["score"]
        package = app_info.get("package", "Target Application")
        fw = tech_info.get("primary_framework", "Native Android")

        # Build executive summary
        summary_paragraphs = [
            f"Automated static security analysis of **{package}** ({fw}) yielded an overall Security Posture Score of **{score}/100** ({score_data['risk_level']}). The audit identified **{counts['CRITICAL']} Critical**, **{counts['HIGH']} High**, and **{counts['MEDIUM']} Medium** risk exposures across decompiled bytecode, manifest configurations, and embedded assets.",
            f"The application's attack surface includes integration with {len(tech_info.get('detected_sdks', []))} third-party cloud SDKs and services. " + 
            ("Immediate remediation is required to revoke exposed production credentials and lock down exported application components before public release." if counts['CRITICAL'] > 0 else "No instant catastrophic credentials were found, but configuration hardening is advised.")
        ]

        # Top 3 Fix These First
        top_priorities = []
        priority_idx = 1
        for f in critical_high[:3]:
            top_priorities.append({
                "priority": priority_idx,
                "title": f["title"],
                "severity": f["severity"],
                "potential_impact": f["impact"],
                "action_required": f["remediation"]
            })
            priority_idx += 1

        recs = [
            "Implement automated pre-commit secret scanning to prevent credential leakage into production APK bundles.",
            "Enforce Network Security Config with certificate pinning on sensitive authentication endpoints.",
            "Set `android:exported=\"false\"` across all internal activities, broadcast receivers, and background services.",
            "Verify all Cloud/BaaS authorization rules (Firebase/Supabase RLS) independently from client assertions."
        ]

        return {
            "score_data": score_data,
            "executive_summary": "\n\n".join(summary_paragraphs),
            "fix_these_first": top_priorities,
            "architectural_recommendations": recs,
            "generated_by": "Local Heuristic Synthesis Engine (Add GEMINI_API_KEY for generative synthesis)"
        }
