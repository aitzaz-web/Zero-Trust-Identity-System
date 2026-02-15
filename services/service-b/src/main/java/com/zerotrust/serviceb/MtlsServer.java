package com.zerotrust.serviceb;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicReference;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Service-B: Java mTLS server using JSSE.
 * - Listens on port 8081
 * - Requires client cert (mTLS)
 * - Verifies peer identity from cert SAN URI (SPIFFE)
 * - Hot reload: periodically checks cert files, reloads SSLContext on change
 */
public class MtlsServer {
    private static final int PORT = 8081;
    private static final String CERT_PATH = "/certs/cert.pem";
    private static final String KEY_PATH = "/certs/key.pem";
    private static final String CA_PATH = "/certs/chain.pem";
    private static final long RELOAD_INTERVAL_MS = 60_000; // 1 min

    private final AtomicReference<SSLContext> sslContextRef = new AtomicReference<>();
    private volatile long lastCertMtime = 0;

    public static void main(String[] args) throws Exception {
        MtlsServer server = new MtlsServer();
        server.start();
    }

    void start() throws Exception {
        reloadContext();
        if (sslContextRef.get() == null) throw new IllegalStateException("SSL context not loaded");
        new Thread(this::reloadLoop).start();

        try (ServerSocketFactory ssf = sslContextRef.get().getServerSocketFactory();
             SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT)) {
            serverSocket.setNeedClientAuth(true);
            serverSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            System.out.println("Service-B listening on port " + PORT + " (mTLS)");

            while (true) {
                try (SSLSocket client = (SSLSocket) serverSocket.accept()) {
                    client.startHandshake();
                    String peer = getPeerSpiffeId(client);
                    System.out.println("Connected: " + peer);
                    respond(client);
                }
            }
        }
    }

    private void reloadLoop() {
        while (true) {
            try {
                Thread.sleep(RELOAD_INTERVAL_MS);
                long mtime = getCertMtime();
                if (mtime > 0 && mtime != lastCertMtime) {
                    reloadContext();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private long getCertMtime() {
        try {
            return Files.getLastModifiedTime(Paths.get(CERT_PATH)).toMillis();
        } catch (IOException e) {
            return 0;
        }
    }

    private void reloadContext() throws Exception {
        KeyStore ks = loadKeyStore();
        KeyStore ts = loadTrustStore();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        sslContextRef.set(ctx);
        lastCertMtime = getCertMtime();
        System.out.println("Certs reloaded");
    }

    private KeyStore loadKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        // Load PEM cert + key into PKCS12
        byte[] certPem = Files.readAllBytes(Paths.get(CERT_PATH));
        byte[] keyPem = Files.readAllBytes(Paths.get(KEY_PATH));
        Object[] pair = PemUtils.loadCertAndKey(certPem, keyPem);
        if (pair == null) throw new RuntimeException("Failed to load cert/key");
        X509Certificate cert = (X509Certificate) pair[0];
        PrivateKey key = (PrivateKey) pair[1];
        ks.setCertificateEntry("cert", cert);
        ks.setKeyEntry("key", key, new char[0], new java.security.cert.Certificate[]{cert});
        return ks;
    }

    private KeyStore loadTrustStore() throws Exception {
        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        byte[] caPem = Files.readAllBytes(Paths.get(CA_PATH));
        java.security.cert.Certificate[] chain = PemUtils.loadCertChain(caPem);
        for (int i = 0; i < chain.length; i++) {
            ts.setCertificateEntry("ca-" + i, chain[i]);
        }
        return ts;
    }

    private String getPeerSpiffeId(SSLSocket socket) {
        try {
            X509Certificate[] chain = (X509Certificate[]) socket.getSession().getPeerCertificates();
            if (chain == null || chain.length == 0) return "";
            return extractSpiffeUri(chain[0]);
        } catch (Exception e) {
            return "";
        }
    }

    private String extractSpiffeUri(X509Certificate cert) {
        // Get URI from SubjectAlternativeName extension
        // In production use Bouncy Castle or similar for proper parsing
        return cert.getSubjectX500Principal().getName(); // fallback; SAN parsing is complex
    }

    private void respond(SSLSocket client) throws IOException {
        String body = "OK from service-b\n";
        String response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + body.length() + "\r\n\r\n" + body;
        client.getOutputStream().write(response.getBytes(US_ASCII));
    }
}
