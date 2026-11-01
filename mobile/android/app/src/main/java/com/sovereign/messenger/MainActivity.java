package com.sovereign.messenger;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.getcapacitor.BridgeActivity;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 1. Запрос нативных разрешений Android (Камера, Микрофон) при старте
        String[] permissions = new String[] {
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.MODIFY_AUDIO_SETTINGS
        };

        List<String> needed = new ArrayList<>();
        for (String perm : permissions) {
            if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {
                needed.add(perm);
            }
        }

        if (!needed.isEmpty()) {
            ActivityCompat.requestPermissions(this, needed.toArray(new String[0]), 101);
        }

        // 2. Оптимизация WebView для аудио/видео стримов
        try {
            WebView webView = this.bridge.getWebView();
            if (webView != null) {
                WebSettings settings = webView.getSettings();
                settings.setDomStorageEnabled(true);
                settings.setDatabaseEnabled(true);
                settings.setJavaScriptEnabled(true);
                settings.setMediaPlaybackRequiresUserGesture(false);
            }
        } catch (Exception ignored) {}
    }

    @Override
    public void onBackPressed() {
        try {
            WebView webView = this.bridge.getWebView();
            if (webView != null) {
                webView.evaluateJavascript("window.handleAndroidBack ? window.handleAndroidBack() : false", value -> {
                    if (!"true".equalsIgnoreCase(value)) {
                        runOnUiThread(() -> MainActivity.super.onBackPressed());
                    }
                });
                return;
            }
        } catch (Exception ignored) {}
        super.onBackPressed();
    }
}
