package io.github.aviraxp.keystoreinjection;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.regex.Pattern;

public class CertUtils {
    private static final Pattern lineTrimmer = Pattern.compile("^\\s+|\\s+$", Pattern.MULTILINE);

    public static Certificate parseCert(String cert) throws Throwable {
        cert = lineTrimmer.matcher(cert).replaceAll("");
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }

        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());

        return (new JcaX509CertificateConverter().getCertificate(holder));
    }

    public static X500Name parseCertSubject(String cert) throws Throwable {
        cert = lineTrimmer.matcher(cert).replaceAll("");
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }

        X509CertificateHolder holder = new X509CertificateHolder(pemObject.getContent());

        return holder.getSubject();
    }

    public static KeyPair parseKeyPair(String key) throws Throwable {
        key = lineTrimmer.matcher(key).replaceAll("");
        Object object;
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            object = parser.readObject();
        }

        PEMKeyPair pemKeyPair = (PEMKeyPair) object;

        return new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
    }

    public static PrivateKey parsePrivateKey(String keyPair) throws RuntimeException {
        keyPair = lineTrimmer.matcher(keyPair).replaceAll("");
        try (PEMParser parser = new PEMParser(new StringReader(keyPair))) {
            PEMKeyPair pemKeyPair = (PEMKeyPair) parser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
