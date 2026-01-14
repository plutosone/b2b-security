package org.plutos.one.util;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@ApplicationScoped
public class CertificateLoader {

    private static final Logger LOG = Logger.getLogger(CertificateLoader.class);

    @ConfigProperty(name = "plutos.private.key.path")
    String plutosPrivateKeyPath;

    @ConfigProperty(name = "plutos.public.key.path")
    String plutosPublicKeyPath;

    @ConfigProperty(name = "b2b.public.key.path")
    String ibmbPublicKeyPath;

    private String plutosPrivateKey;
    private String plutosPublicKey;
    private String ibmbPublicKey;

    private PrivateKey plutosPrivateKeyObj;
    private PublicKey plutosPublicKeyObj;
    private PublicKey ibmbPublicKeyObj;

    @PostConstruct
    void loadCertificates() {
        try {
            validatePaths();

            plutosPrivateKey = Files.readString(Paths.get(plutosPrivateKeyPath));
            plutosPublicKey = Files.readString(Paths.get(plutosPublicKeyPath));
            ibmbPublicKey = Files.readString(Paths.get(ibmbPublicKeyPath));

            plutosPrivateKeyObj = parseECPrivateKey(plutosPrivateKey);
            plutosPublicKeyObj = parseECPublicKey(plutosPublicKey);
            ibmbPublicKeyObj = parseECPublicKey(ibmbPublicKey);

            LOG.info("Certificates loaded and parsed successfully");
        } catch (Exception e) {
            LOG.error("Failed to load certificates", e);
            throw new RuntimeException("Certificate loading failed", e);
        }
    }

    private void validatePaths() {
        if (!Files.exists(Paths.get(plutosPrivateKeyPath))) {
            throw new RuntimeException("Private key file not found: " + plutosPrivateKeyPath);
        }
        if (!Files.exists(Paths.get(plutosPublicKeyPath))) {
            throw new RuntimeException("Public key file not found: " + plutosPublicKeyPath);
        }
        if (!Files.exists(Paths.get(ibmbPublicKeyPath))) {
            throw new RuntimeException("IBMB public key file not found: " + ibmbPublicKeyPath);
        }
    }

    private PrivateKey parseECPrivateKey(String pem) throws Exception {
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("EC").generatePrivate(keySpec);
    }

    private PublicKey parseECPublicKey(String pem) throws Exception {
        String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("EC").generatePublic(keySpec);
    }

    public PublicKey parseRSAPublicKey(String pem) throws Exception {
        String clean = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(clean);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public PrivateKey parseRSAPrivateKey(String pem) throws Exception {
        String clean = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] encoded = Base64.getDecoder().decode(clean);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public String getPlutosPrivateKey() {
        return plutosPrivateKey;
    }

    public String getPlutosPublicKey() {
        return plutosPublicKey;
    }

    public String getIbmbPublicKey() {
        return ibmbPublicKey;
    }

    public PrivateKey getPlutosPrivateKeyObj() {
        return plutosPrivateKeyObj;
    }

    public PublicKey getPlutosPublicKeyObj() {
        return plutosPublicKeyObj;
    }

    public PublicKey getIbmbPublicKeyObj() {
        return ibmbPublicKeyObj;
    }

    

    public boolean isHealthy() {
        return plutosPrivateKeyObj != null && plutosPublicKeyObj != null && ibmbPublicKeyObj != null;
    }
}