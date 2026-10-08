import os
import zipfile

def create_sample_vulnerable_apk():
    samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
    os.makedirs(samples_dir, exist_ok=True)
    apk_path = os.path.join(samples_dir, "vulnerable_demo_app.apk")

    manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.security.vulnerableapp"
    android:versionCode="1"
    android:versionName="1.0.0">

    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="31" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:icon="@mipmap/ic_launcher"
        android:label="Vulnerable Banking App">

        <!-- Exported Activity without permission -->
        <activity
            android:name="com.security.vulnerableapp.AdminDashboardActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:scheme="vulnerableapp" android:host="admin" />
            </intent-filter>
        </activity>

        <activity
            android:name="com.security.vulnerableapp.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Exported Service -->
        <service
            android:name="com.security.vulnerableapp.PaymentSyncService"
            android:exported="true" />

    </application>
</manifest>
"""

    stripe_dummy = "sk_" + "live_" + "51HzExampleStripeLiveKey123"
    api_client_java = f"""package com.security.vulnerableapp;

public class ApiClient {{
    // Harmless Public Identifiers (Should NOT trigger Critical)
    public static final String FIREBASE_API_KEY = "AIzaSyD9xExampleSecretFirebaseKey123456";
    public static final String GOOGLE_MAPS_KEY = "AIzaSyB_SampleGoogleMapsAndroidKey789012";
    public static final String SENTRY_DSN = "https://a1b2c3d4e5f67890@sentry.io/1234567";

    // 🔴 CRITICAL HARDCODED SECRETS
    public static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    public static final String STRIPE_SECRET = "{stripe_dummy}";
    public static final String DATABASE_URL = "postgres://admin:SuperSecretPass123@db.prod.company.com:5432/main";
    public static final String SUPABASE_SERVICE_ROLE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.ExampleSuperSecretSupabaseServiceKey999";
}}
"""

    webview_activity_java = """package com.security.vulnerableapp;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import javax.crypto.Cipher;

public class WebViewActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        
        // Insecure WebView Configuration
        webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
        webView.getSettings().setAllowFileAccessFromFileURLs(true);
        
        try {
            // Weak Cryptography
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            Cipher desCipher = Cipher.getInstance("DES");
        } catch (Exception e) {}
    }
}
"""

    with zipfile.ZipFile(apk_path, 'w') as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
        zf.writestr("sources/com/security/vulnerableapp/ApiClient.java", api_client_java)
        zf.writestr("sources/com/security/vulnerableapp/WebViewActivity.java", webview_activity_java)
        zf.writestr("assets/config.json", '{"environment": "production", "api_endpoint": "https://staging.internal.company.com/v1"}')
        zf.writestr("classes.dex", b"DEX_PLACEHOLDER")

    print(f"[CREATED] Sample vulnerable APK created at: {apk_path}")
    return apk_path

if __name__ == "__main__":
    create_sample_vulnerable_apk()
