package com.ryanheise.just_audio;

import io.flutter.Log;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

class MtlsHelper {
    private static final String TAG = "MtlsHelper";

    static synchronized void configure(byte[] p12Bytes, String password) {
        try {
            char[] pwd = password != null ? password.toCharArray() : new char[0];
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new ByteArrayInputStream(p12Bytes), pwd);
            KeyManagerFactory kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pwd);
            SSLContext sslCtx = SSLContext.getInstance("TLS");
            sslCtx.init(kmf.getKeyManagers(), null, null);
            // Set globally so ExoPlayer's DefaultHttpDataSource (which opens
            // plain HttpURLConnection/HttpsURLConnection) picks up the client cert.
            // There is no per-connection injection point on DefaultHttpDataSource.
            HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());
            Log.i(TAG, "mTLS client certificate configured");
        } catch (Exception e) {
            Log.e(TAG, "Failed to configure mTLS: " + e.getMessage());
        }
    }

    static synchronized void clear() {
        try {
            // setDefaultSSLSocketFactory(null) throws NPE; restore the JVM default instead.
            HttpsURLConnection.setDefaultSSLSocketFactory(
                    SSLContext.getDefault().getSocketFactory());
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to reset SSL factory: " + e.getMessage());
        }
        Log.i(TAG, "mTLS client certificate cleared");
    }
}
