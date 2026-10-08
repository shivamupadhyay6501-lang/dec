# 🛡️ APK Security Intelligence & Executive Auditor

An automated, evidence-driven Android APK static analysis and AI-powered security auditing platform.

Built around **security properties rather than frameworks**—automatically detects whether an app is **Flutter, React Native, Native Kotlin/Java, or Unity**, extracts actionable evidence, classifies genuine secrets from public identifiers, and uses **Google Gemini** to produce crystal-clear executive reports and step-by-step developer remediation.

---

## 🌟 Key Features

1. **Automatic Technology Detection**:
   - Accurately identifies Flutter (Dart AOT binaries), React Native (Hermes bytecode & JS bundles), Native Kotlin/Java, Unity, Cordova/Capacitor.
   - Discovers third-party cloud SDKs (Firebase, AWS, GCP, Supabase, Stripe, Sentry, GraphQL).

2. **Play Store Link to Decompiled Code**:
   - Paste any Google Play URL (e.g. `https://play.google.com/store/apps/details?id=...`) or package name.
   - Automatically downloads the APK from high-speed mirror endpoints and passes it to JADX.

3. **Smart Secret Classifier & False-Positive Filter**:
   - Calculates **Shannon Entropy** to discover suspicious random tokens.
   - Distinguishes **dangerous production credentials** (AWS Secret Keys, Stripe live secrets, Service Account JSONs, Database URLs, Private Keys) from **benign client identifiers** (Google Maps SDK key restricted by SHA-1, public Firebase Web API key, Sentry DSN, public Supabase anon key).

4. **Code & Manifest Security Engine**:
   - **Manifest**: Insecure `debuggable`, `allowBackup`, `usesCleartextTraffic`, exported components without permissions, custom deep link schemes.
   - **Code**: Broken cryptography (`DES`, `AES/ECB`, `MD5`), insecure WebViews (`addJavascriptInterface`, `handler.proceed()`), TLS verification bypass (`TrustAllCerts`, `AllowAllHostnameVerifier`), world-readable storage.
   - **Cloud Prober**: Non-destructive passive checks for open Firebase Realtime Databases (`/.json`) and publicly listable S3 buckets.

5. **Gemini Executive AI Synthesis**:
   - Synthesizes findings into an executive briefing, deterministic Security Score (0–100), and a prioritized **"🔥 Fix These FIRST"** action list with blast radius calculations.
   - Works 100% offline with a built-in heuristic synthesizer, or with **Google Gemini 2.5 Flash** ($0 free tier).

6. **Release Regression System (v4.7 vs v4.8)**:
   - Tracks vulnerability progression across app versions.
   - Visualizes resolved vulnerabilities, newly introduced risks, and score changes.

7. **100% Free Compute Options**:
   - **Local Server**: Run locally on your machine with FastAPI.
   - **Cloud CI/CD**: Run on GitHub Actions (4 vCPU, 16GB RAM) for $0 using the included `.github/workflows/apk_audit.yml`.

---

## 🚀 Quick Start

### 1. Requirements
- **Python 3.10+**
- **Java 17+** (OpenJDK / Oracle JRE)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Web Dashboard
```bash
python run.py
```
Open your browser at **[http://localhost:8000](http://localhost:8000)**.

---

## 💻 CLI Usage

You can also run scans directly from your terminal:

```bash
# Scan a Play Store app by package name or URL
python run.py scan --target com.spotify.music

# Run internal unit tests
python run.py test
```

---

## ⚙️ Google Gemini AI Configuration (Free Tier)

1. Get a free API key at [Google AI Studio](https://aistudio.google.com/).
2. Set it in your environment:
   ```bash
   export GEMINI_API_KEY="AIzaSy..."  # Linux / macOS
   set GEMINI_API_KEY="AIzaSy..."     # Windows CMD
   $env:GEMINI_API_KEY="AIzaSy..."    # Windows PowerShell
   ```
   *Alternatively, enter the key directly in the Dashboard Settings tab (saved in local storage).*

---

## ☁️ Running for $0 on GitHub Actions

This repository includes a ready-to-use GitHub Actions workflow (`.github/workflows/apk_audit.yml`):

1. Push this repository to GitHub.
2. Add `GEMINI_API_KEY` to **Repository Secrets** (optional).
3. Go to **Actions** -> **APK Security Audit & Executive Report** -> **Run workflow**.
4. Paste the Play Store link or package name.
5. GitHub will spin up a 16GB RAM runner, decompile, audit, and output the report artifact for $0!
