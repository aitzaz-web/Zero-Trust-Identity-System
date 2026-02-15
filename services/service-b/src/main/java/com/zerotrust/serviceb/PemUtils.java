package com.zerotrust.serviceb;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.*;

/**
 * Simple PEM parser for cert and key (MVP; use Bouncy Castle for production).
 */
public final class PemUtils {
    private PemUtils() {}

    public static Object[] loadCertAndKey(byte[] certPem, byte[] keyPem) throws Exception {
        X509Certificate cert = (X509Certificate) loadPem(certPem, "CERTIFICATE");
        if (cert == null) return null;
        PrivateKey key = (PrivateKey) loadPem(keyPem, "RSA PRIVATE KEY");
        if (key == null) key = (PrivateKey) loadPem(keyPem, "PRIVATE KEY");
        if (key == null) return null;
        return new Object[]{cert, key};
    }

    public static Certificate[] loadCertChain(byte[] pem) throws Exception {
        List<Certificate> certs = new ArrayList<>();
        String content = new String(pem, java.nio.charset.StandardCharsets.UTF_8);
        Pattern p = Pattern.compile("-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----");
        Matcher m = p.matcher(content);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (m.find()) {
            byte[] der = Base64.getMimeDecoder().decode(m.group(1).replaceAll("\\s", ""));
            certs.add(cf.generateCertificate(new ByteArrayInputStream(der)));
        }
        return certs.toArray(new Certificate[0]);
    }

    private static Object loadPem(byte[] pem, String type) throws Exception {
        String content = new String(pem, java.nio.charset.StandardCharsets.UTF_8);
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int s = content.indexOf(begin);
        int e = content.indexOf(end);
        if (s < 0 || e < 0) return null;
        String b64 = content.substring(s + begin.length(), e).replaceAll("\\s", "");
        byte[] der = Base64.getMimeDecoder().decode(b64);
        if (type.contains("CERTIFICATE")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return cf.generateCertificate(new ByteArrayInputStream(der));
        }
        if (type.contains("PRIVATE")) {
            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(der);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
        if (type.contains("RSA PRIVATE")) {
            java.security.spec.PKCS8EncodedKeySpec spec = convertPkcs1ToPkcs8(der);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
        return null;
    }

    private static java.security.spec.PKCS8EncodedKeySpec convertPkcs1ToPkcs8(byte[] pkcs1) {
        // PKCS#1 to PKCS#8: wrap in AlgorithmIdentifier + OCTET STRING
        // 30 82 xx xx  SEQUENCE
        //   02 01 00     INTEGER 0 (version)
        //   30 0d       SEQUENCE AlgorithmIdentifier
        //     06 09 2a 86 48 86 f7 0d 01 01 01  rsaEncryption OID
        //     05 00       NULL
        //   04 82 xx xx  OCTET STRING (pkcs1 key)
        byte[] oid = new byte[]{0x30, 0x0d, 0x06, 0x09, 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
        int total = 4 + oid.length + 4 + pkcs1.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(0x30); out.write(0x82); out.write((total >> 8) & 0xff); out.write(total & 0xff);
            out.write(0x02); out.write(0x01); out.write(0);
            out.write(oid);
            out.write(0x04); out.write(0x82); out.write((pkcs1.length >> 8) & 0xff); out.write(pkcs1.length & 0xff);
            out.write(pkcs1);
        } catch (IOException e) { throw new RuntimeException(e); }
        return new java.security.spec.PKCS8EncodedKeySpec(out.toByteArray());
    }
}
