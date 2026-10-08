import os
import xml.etree.ElementTree as ET
import logging
from typing import Dict, Any, List, Optional
try:
    from pyaxmlparser import APK
except ImportError:
    APK = None

logger = logging.getLogger("scanner.manifest_analyzer")

class ManifestAnalyzer:
    """
    Parses and audits AndroidManifest.xml for configuration flaws,
    exported components, insecure network flags, deep links, and excessive permissions.
    """

    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_EXTERNAL_STORAGE": {
            "title": "Legacy External Storage Read",
            "desc": "Permits reading shared public storage where other apps can drop or read files.",
            "severity": "LOW"
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "title": "Legacy External Storage Write",
            "desc": "Permits modifying files in shared public storage.",
            "severity": "LOW"
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            "title": "Overlay Permission (Draw on Top)",
            "desc": "Can be abused for tapjacking and overlay attacks to steal credentials.",
            "severity": "MEDIUM"
        },
        "android.permission.REQUEST_INSTALL_PACKAGES": {
            "title": "Request Install Packages",
            "desc": "Allows app to trigger arbitrary APK installation from local storage.",
            "severity": "MEDIUM"
        },
        "android.permission.ACCESS_FINE_LOCATION": {
            "title": "Precise GPS Location",
            "desc": "Accesses precise user geographic coordinates.",
            "severity": "INFO"
        },
        "android.permission.RECORD_AUDIO": {
            "title": "Microphone Audio Recording",
            "desc": "Permits continuous microphone recording.",
            "severity": "INFO"
        },
        "android.permission.CAMERA": {
            "title": "Camera Capture",
            "desc": "Permits capturing photos and video streams.",
            "severity": "INFO"
        }
    }

    def analyze_from_apk(self, apk_path: str) -> Dict[str, Any]:
        """Direct extraction using pyaxmlparser without decompilation."""
        if not APK:
            return {"error": "pyaxmlparser not installed"}

        try:
            apk = APK(apk_path)
            raw_xml_str = apk.get_android_manifest_axml()
            # If pyaxmlparser has xml string
            manifest_xml = apk.xml.get("AndroidManifest.xml", "")
            return self._evaluate_manifest(
                package=apk.package,
                version_name=apk.version_name,
                version_code=apk.version_code,
                min_sdk=apk.get_min_sdk_version(),
                target_sdk=apk.get_target_sdk_version(),
                permissions=apk.get_permissions(),
                activities=apk.get_activities(),
                services=apk.get_services(),
                receivers=apk.get_receivers(),
                providers=apk.get_providers(),
                raw_xml=str(manifest_xml) if manifest_xml else ""
            )
        except Exception as e:
            logger.error(f"Error parsing manifest via pyaxmlparser: {e}")
            return {"error": str(e)}

    def analyze_from_file(self, manifest_xml_path: str) -> Dict[str, Any]:
        """Parses decoded XML file from JADX resources."""
        if not os.path.exists(manifest_xml_path):
            return {"error": f"Manifest not found at {manifest_xml_path}"}

        try:
            tree = ET.parse(manifest_xml_path)
            root = tree.getroot()

            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            
            package = root.attrib.get('package', 'unknown')
            version_code = root.attrib.get(f'{{{ns["android"]}}}versionCode', 'unknown')
            version_name = root.attrib.get(f'{{{ns["android"]}}}versionName', 'unknown')

            uses_sdk = root.find('uses-sdk')
            min_sdk = uses_sdk.attrib.get(f'{{{ns["android"]}}}minSdkVersion') if uses_sdk is not None else 'Unknown'
            target_sdk = uses_sdk.attrib.get(f'{{{ns["android"]}}}targetSdkVersion') if uses_sdk is not None else 'Unknown'

            permissions = [p.attrib.get(f'{{{ns["android"]}}}name') for p in root.findall('uses-permission') if p.attrib.get(f'{{{ns["android"]}}}name')]

            application = root.find('application')
            app_flags = {}
            activities, services, receivers, providers = [], [], [], []
            exported_components = []
            deep_links = []

            if application is not None:
                # App flags
                app_flags = {
                    "debuggable": application.attrib.get(f'{{{ns["android"]}}}debuggable') == "true",
                    "allowBackup": application.attrib.get(f'{{{ns["android"]}}}allowBackup', 'true') == 'true',
                    "usesCleartextTraffic": application.attrib.get(f'{{{ns["android"]}}}usesCleartextTraffic') == "true",
                    "networkSecurityConfig": application.attrib.get(f'{{{ns["android"]}}}networkSecurityConfig')
                }

                # Helper to check components
                for comp_tag, comp_list, comp_type in [
                    ('activity', activities, 'Activity'),
                    ('service', services, 'Service'),
                    ('receiver', receivers, 'BroadcastReceiver'),
                    ('provider', providers, 'ContentProvider')
                ]:
                    for elem in application.findall(comp_tag):
                        name = elem.attrib.get(f'{{{ns["android"]}}}name', 'unknown')
                        comp_list.append(name)
                        
                        is_exported = elem.attrib.get(f'{{{ns["android"]}}}exported')
                        has_filter = len(elem.findall('intent-filter')) > 0
                        permission = elem.attrib.get(f'{{{ns["android"]}}}permission')

                        # Android default rule: if has intent-filter and exported not explicitly false => exported=true
                        exported = (is_exported == 'true') or (is_exported is None and has_filter)
                        
                        if exported:
                            exported_components.append({
                                "type": comp_type,
                                "name": name,
                                "permission": permission,
                                "guarded": permission is not None
                            })

                        # Extract Deep Links from intent-filters
                        for ifilter in elem.findall('intent-filter'):
                            for data in ifilter.findall('data'):
                                scheme = data.attrib.get(f'{{{ns["android"]}}}scheme')
                                host = data.attrib.get(f'{{{ns["android"]}}}host')
                                if scheme:
                                    deep_links.append({
                                        "component": name,
                                        "scheme": scheme,
                                        "host": host or "",
                                        "autoVerify": ifilter.attrib.get(f'{{{ns["android"]}}}autoVerify') == "true"
                                    })

            with open(manifest_xml_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_xml = f.read()

            return self._build_findings(
                package=package,
                version_name=version_name,
                version_code=version_code,
                min_sdk=min_sdk,
                target_sdk=target_sdk,
                permissions=permissions,
                app_flags=app_flags,
                exported_components=exported_components,
                deep_links=deep_links,
                raw_xml=raw_xml
            )

        except Exception as e:
            logger.error(f"Error parsing manifest XML file: {e}")
            return {"error": str(e)}

    def _build_findings(self, package, version_name, version_code, min_sdk, target_sdk, permissions, app_flags, exported_components, deep_links, raw_xml):
        findings = []

        # 1. Debuggable Check
        if app_flags.get("debuggable") is True:
            findings.append({
                "id": "MAN-001",
                "category": "Application Configuration",
                "title": "Production APK is Debuggable",
                "severity": "CRITICAL",
                "confidence": 1.0,
                "exposure": "Publicly exploitable via ADB",
                "evidence": {
                    "flag": "android:debuggable=\"true\"",
                    "file": "AndroidManifest.xml"
                },
                "impact": "An attacker can attach a debugger (JDWP), inspect application heap memory, extract runtime encryption keys, or hijack control flow.",
                "remediation": "Set `android:debuggable=\"false\"` in `AndroidManifest.xml` or ensure your release buildType disables debug flags in build.gradle."
            })

        # 2. AllowBackup Check
        if app_flags.get("allowBackup") is True:
            findings.append({
                "id": "MAN-002",
                "category": "Data Storage & Privacy",
                "title": "Application Allows ADB Data Backup",
                "severity": "MEDIUM",
                "confidence": 0.95,
                "exposure": "Local physical or ADB access",
                "evidence": {
                    "flag": "android:allowBackup=\"true\"",
                    "file": "AndroidManifest.xml"
                },
                "impact": "Anyone with physical or USB debugging access can extract internal app databases, cache, and SharedPreferences via `adb backup`.",
                "remediation": "Set `android:allowBackup=\"false\"` in the `<application>` tag of `AndroidManifest.xml` unless enterprise backup is explicitly required."
            })

        # 3. Cleartext HTTP Traffic
        if app_flags.get("usesCleartextTraffic") is True:
            findings.append({
                "id": "MAN-003",
                "category": "Network Security",
                "title": "Cleartext HTTP Traffic Allowed",
                "severity": "HIGH",
                "confidence": 0.95,
                "exposure": "Network eavesdropping / MITM",
                "evidence": {
                    "flag": "android:usesCleartextTraffic=\"true\"",
                    "file": "AndroidManifest.xml"
                },
                "impact": "The app is permitted to communicate over unencrypted HTTP, allowing man-in-the-middle attackers on public Wi-Fi to intercept or alter API requests.",
                "remediation": "Set `android:usesCleartextTraffic=\"false\"` and enforce strict HTTPS TLS 1.3 across all backend endpoints."
            })

        # 4. Unguarded Exported Components
        unguarded_exported = [c for c in exported_components if not c["guarded"]]
        if len(unguarded_exported) > 0:
            sample_components = [f"{c['type']}: {c['name'].split('.')[-1]}" for c in unguarded_exported[:5]]
            findings.append({
                "id": "MAN-004",
                "category": "Android Component Exposure",
                "title": f"Exported Components Without Permission Protection ({len(unguarded_exported)} detected)",
                "severity": "HIGH" if any(c['type'] in ['Service', 'ContentProvider'] for c in unguarded_exported) else "MEDIUM",
                "confidence": 0.9,
                "exposure": "Locally exploitable by other apps on device",
                "evidence": {
                    "total_unguarded": len(unguarded_exported),
                    "samples": sample_components,
                    "file": "AndroidManifest.xml"
                },
                "impact": "Malicious 3rd-party apps installed on the same phone can trigger these internal activities or bind to background services without authorization.",
                "remediation": "Add `android:exported=\"false\"` for internal components or protect them with `android:permission`."
            })

        # 5. Insecure Custom Scheme Deep Links
        custom_schemes = [d for d in deep_links if d["scheme"] not in ["http", "https"]]
        if len(custom_schemes) > 0:
            sample_schemes = list(set(d["scheme"] for d in custom_schemes))
            findings.append({
                "id": "MAN-005",
                "category": "Deep Link Security",
                "title": f"Insecure Custom URI Schemes Registered ({', '.join(sample_schemes)})",
                "severity": "LOW",
                "confidence": 0.85,
                "exposure": "Phishing / Intent Redirection",
                "evidence": {
                    "schemes": sample_schemes,
                    "total_links": len(custom_schemes),
                    "file": "AndroidManifest.xml"
                },
                "impact": "Custom URI schemes (e.g. `myapp://`) are not claimed exclusively by Android. Other malicious apps can register the same scheme to hijack incoming deep links.",
                "remediation": "Migrate to Android App Links (`https://yourdomain.com/...`) with `android:autoVerify=\"true\"` and a valid `assetlinks.json` domain proof."
            })

        # 6. Check Target SDK Version
        try:
            target_sdk_int = int(target_sdk)
            if target_sdk_int < 33:
                findings.append({
                    "id": "MAN-006",
                    "category": "Platform Compliance",
                    "title": f"Outdated Target SDK Version (API {target_sdk})",
                    "severity": "LOW",
                    "confidence": 1.0,
                    "evidence": {
                        "targetSdkVersion": target_sdk,
                        "recommended": "34+"
                    },
                    "impact": "Targeting older Android API levels misses modern security enhancements like notification permissions, photo picker isolation, and granular media controls.",
                    "remediation": "Update `targetSdkVersion` to 34 or 35 in your `build.gradle`."
                })
        except (ValueError, TypeError):
            pass

        return {
            "package": package,
            "version_name": version_name,
            "version_code": version_code,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "permissions": permissions,
            "app_flags": app_flags,
            "exported_components_count": len(exported_components),
            "unguarded_exported_count": len(unguarded_exported),
            "deep_links_count": len(deep_links),
            "findings": findings
        }
