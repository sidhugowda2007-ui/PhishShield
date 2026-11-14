package com.phishguard.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Receives links tapped in other apps (when PhishGuard is chosen to open links) and text shared to PhishGuard.
 * Low risk: forwards to the real browser instantly with no UI. Medium/high: shows the warning screen first.
 */
public class LinkCheckActivity extends Activity {
    private String url;
    private Analyzer.Verdict verdict;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        url = extractUrl(getIntent());
        if (url == null) { Toast.makeText(this, R.string.no_link, Toast.LENGTH_SHORT).show(); finish(); return; }
        verdict = Analyzer.analyzeUrl(url);
        String source = Intent.ACTION_SEND.equals(getIntent().getAction()) ? "share" : "link-tap";
        ScanStore.add(this, url, verdict, source);
        if ("low".equals(verdict.level)) { forwardAndFinish(); return; }
        showWarning();
    }

    private static String extractUrl(Intent intent) {
        if (intent == null) return null;
        if (Intent.ACTION_SEND.equals(intent.getAction())) {
            List<String> urls = UrlExtractor.extract(intent.getStringExtra(Intent.EXTRA_TEXT), 1);
            return urls.isEmpty() ? null : urls.get(0);
        }
        if (intent.getData() == null) return null;
        String s = intent.getData().toString();
        return s.regionMatches(true, 0, "http://", 0, 7) || s.regionMatches(true, 0, "https://", 0, 8) ? s : null;
    }

    private void forwardAndFinish() {
        if (!BrowserForwarder.open(this, url)) Toast.makeText(this, R.string.no_browser, Toast.LENGTH_LONG).show();
        finish();
    }

    private void showWarning() {
        WebView web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#F4F6FB"));
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setAllowFileAccess(false);        // does not affect file:///android_asset
        s.setAllowContentAccess(false);
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView v, android.webkit.WebResourceRequest r) { return true; }
        });
        web.addJavascriptInterface(new Object() {
            @JavascriptInterface public String getWarning() {
                try {
                    JSONArray arr = new JSONArray();
                    for (Analyzer.Indicator i : verdict.indicators) arr.put(new JSONObject().put("label", i.label).put("points", i.points));
                    return new JSONObject().put("url", url).put("score", verdict.score).put("level", verdict.level).put("indicators", arr).toString();
                } catch (Exception e) { return "{}"; }
            }
            @JavascriptInterface public void back() { runOnUiThread(LinkCheckActivity.this::finish); }
            @JavascriptInterface public void proceed() { runOnUiThread(LinkCheckActivity.this::forwardAndFinish); }
        }, "PG");
        setContentView(web);
        web.loadUrl("file:///android_asset/web/warning.html");
    }
}
