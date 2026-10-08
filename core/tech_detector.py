import os
import re
import logging
from typing import Dict, Any, List, Set

logger = logging.getLogger("scanner.tech_detector")

class TechnologyDetector:
    """
    Identifies the underlying mobile framework, architecture, cloud providers,
    analytics platforms, and networking libraries from an unpacked APK.
    """

    FRAMEWORK_SIGNATURES = {
        "Flutter": {
            "files": ["libflutter.so", "libapp.so", "assets/flutter_assets"],
            "classes": ["io.flutter.app", "io.flutter.embedding"],
            "description": "Google Flutter (Dart AOT compiled)"
        },
        "React Native": {
            "files": ["assets/index.android.bundle", "libreactnativejni.so", "libhermes.so"],
            "classes": ["com.facebook.react"],
            "description": "Meta React Native (Hermes / JavaScript)"
        },
        "Unity": {
            "files": ["libunity.so", "libil2cpp.so", "assets/bin/Data"],
            "classes": ["com.unity3d.player"],
            "description": "Unity 3D Engine (IL2CPP / Mono)"
        },
        "Cordova / Capacitor": {
            "files": ["assets/www/index.html", "assets/public/index.html"],
            "classes": ["org.apache.cordova", "com.getcapacitor"],
            "description": "Apache Cordova / Ionic Capacitor (Hybrid WebView)"
        },
        "Xamarin / .NET MAUI": {
            "files": ["libmonosgen-2.0.so", "assemblies"],
            "classes": ["mono.android"],
            "description": "Microsoft Xamarin / .NET MAUI"
        },
        "Native Android (Kotlin / Java)": {
            "files": [],
            "classes": ["androidx.", "kotlin."],
            "description": "Native Android (Java & Kotlin bytecode)"
        }
    }

    SDK_SIGNATURES = {
        "Firebase": {
            "patterns": [r"firebaseio\.com", r"com\.google\.firebase", r"google-services\.json", r"firebase_core"],
            "category": "Backend as a Service"
        },
        "AWS (Amazon Web Services)": {
            "patterns": [r"amazonaws\.com", r"com\.amazonaws", r"aws-android-sdk", r"cognito-idp"],
            "category": "Cloud Infrastructure"
        },
        "Google Cloud Platform": {
            "patterns": [r"googleapis\.com", r"com\.google\.api\.client", r"cloud\.google\.com"],
            "category": "Cloud Infrastructure"
        },
        "Supabase": {
            "patterns": [r"supabase\.co", r"io\.supabase", r"supabase-kt"],
            "category": "Backend as a Service"
        },
        "Stripe": {
            "patterns": [r"api\.stripe\.com", r"com\.stripe\.android"],
            "category": "Payment Gateway"
        },
        "Razorpay": {
            "patterns": [r"api\.razorpay\.com", r"com\.razorpay"],
            "category": "Payment Gateway"
        },
        "Sentry": {
            "patterns": [r"sentry\.io", r"io\.sentry"],
            "category": "Crash Reporting & Observability"
        },
        "Bugsnag": {
            "patterns": [r"bugsnag\.com", r"com\.bugsnag"],
            "category": "Crash Reporting & Observability"
        },
        "GraphQL / Apollo": {
            "patterns": [r"com\.apollographql", r"graphql-java"],
            "category": "API Layer"
        },
        "Retrofit / OkHttp": {
            "patterns": [r"retrofit2", r"okhttp3"],
            "category": "Networking"
        },
        "Ktor": {
            "patterns": [r"io\.ktor"],
            "category": "Networking"
        },
        "OneSignal": {
            "patterns": [r"onesignal\.com", r"com\.onesignal"],
            "category": "Push Notifications"
        },
        "AppsFlyer": {
            "patterns": [r"appsflyer\.com", r"com\.appsflyer"],
            "category": "Attribution & Analytics"
        },
        "Mixpanel / Amplitude": {
            "patterns": [r"api\.mixpanel\.com", r"amplitude\.com", r"com\.mixpanel"],
            "category": "Product Analytics"
        }
    }

    def detect(self, extracted_dir: str, file_list: List[str]) -> Dict[str, Any]:
        """
        Scans all files and paths in the unpacked APK to discover the tech stack.
        """
        file_set = set(f.replace("\\", "/") for f in file_list)
        all_paths_str = "\n".join(file_set)

        # 1. Detect Primary Framework
        primary_framework = "Native Android (Kotlin / Java)"
        framework_details = "Native Android (Java & Kotlin bytecode)"

        for fw_name, rules in self.FRAMEWORK_SIGNATURES.items():
            if fw_name == "Native Android (Kotlin / Java)":
                continue
            
            # Check file presence
            matched_file = False
            for target_file in rules["files"]:
                if any(target_file in path for path in file_set):
                    matched_file = True
                    break

            if matched_file:
                primary_framework = fw_name
                framework_details = rules["description"]
                break

        # 2. Detect Architectures & Native Libraries (.so)
        native_archs = set()
        native_libs = set()
        for path in file_set:
            if path.startswith("lib/"):
                parts = path.split("/")
                if len(parts) >= 2:
                    native_archs.add(parts[1])
                if len(parts) >= 3:
                    native_libs.add(parts[2])

        # 3. Detect Cloud Services, Analytics, and SDKs
        detected_sdks: List[Dict[str, str]] = []
        for sdk_name, sdk_info in self.SDK_SIGNATURES.items():
            for pat in sdk_info["patterns"]:
                if re.search(pat, all_paths_str, re.IGNORECASE):
                    detected_sdks.append({
                        "name": sdk_name,
                        "category": sdk_info["category"]
                    })
                    break

        # 4. Check Hermes engine if React Native
        has_hermes = any("libhermes.so" in p for p in file_set)
        if primary_framework == "React Native":
            if has_hermes:
                framework_details += " with Hermes Bytecode Engine"
            else:
                framework_details += " with standard JavaScript Core"

        return {
            "primary_framework": primary_framework,
            "framework_details": framework_details,
            "detected_sdks": detected_sdks,
            "native_architectures": list(native_archs),
            "native_libraries_count": len(native_libs),
            "has_hermes_engine": has_hermes,
            "is_hybrid": primary_framework in ["Flutter", "React Native", "Cordova / Capacitor", "Unity", "Xamarin / .NET MAUI"]
        }
