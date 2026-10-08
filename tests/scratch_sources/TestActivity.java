
    public class InsecureWebViewActivity extends Activity {
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            WebView webView = findViewById(R.id.webview);
            webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
            
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        }
    }
    