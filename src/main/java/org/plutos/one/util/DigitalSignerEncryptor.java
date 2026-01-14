package org.plutos.one.util;

import javax.crypto.Cipher;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Base64;

@ApplicationScoped
public class DigitalSignerEncryptor {

    private static final Logger logger = LoggerFactory.getLogger(DigitalSignerEncryptor.class);

    @Inject
    CertificateLoader certificateLoader;

    @ConfigProperty(name = "bank.id")
    private String BANK_ID;

    @Inject
    ObjectMapper objectMapper;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public Uni<String> encrypt(String request) {

        return Uni.createFrom().item(() -> {
            try {

                // logger.debug("Json request: {}", json);
                PrivateKey privateKey = certificateLoader.getPlutosPrivateKeyObj();

                long created = System.currentTimeMillis();
                long expires = created + 180000;

                String encodedPayload = encodedPayload(certificateLoader.getIbmbPublicKeyObj(), request);
                String encodedProtected = encodedProtected(created, expires);
                String encodedSig = encodedSignature(privateKey, request, created, expires);

                // logger.debug("Signed and encrypted payload: payload={}, protected={},
                // signature={}",
                // encodedPayload, encodedProtected, encodedSig);

                return String.format(
                        "{\n  \"payload\": \"%s\",\n  \"signatures\": [{\n    \"protectedInfo\": \"%s\",\n    \"signature\": \"%s\"\n  }]\n}",
                        encodedPayload, encodedProtected, encodedSig);
            } catch (Exception e) {
                logger.error("Failed to encrypt object", e);
                return "{\"error\": \"Failed to process request: " + e.getMessage() + "\"}";
            }
        }).runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
    }

    private String encodedPayload(PublicKey publicKey, String json) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIESwithSHA512/NONE/NoPadding");
        IESParameterSpec iesParamSpec = new IESParameterSpec(null, null, 256);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, iesParamSpec);
        byte[] encryptedBytes = cipher.doFinal(json.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String encodedProtected(long created, long expires) throws Exception {
        String protectedHeader = String.format(
                "keyId=\"%s|ecdsa\",algorithm=\"ecdsa\",created=\"%d\",expires=\"%d\",headers=\"(created)(expires)digest\"",
                BANK_ID, created, expires);
        String encodedProtected = Base64.getEncoder()
                .encodeToString(protectedHeader.getBytes(StandardCharsets.UTF_8));

        return encodedProtected;
    }

    public String encodedSignature(PrivateKey privateKey, String json, long created,
            long expires)
            throws Exception {
        Blake2bDigest blakeHash = new Blake2bDigest(512);
        blakeHash.update(json.getBytes(), 0, json.getBytes().length);
        byte[] hashByte = new byte[blakeHash.getDigestSize()];
        blakeHash.doFinal(hashByte, 0);

        String concatenated = "(created):" + created + "\n"
                + "(expires):" + expires + "\n" + "digest:BLAKE2b-512="
                + Base64.getEncoder().encodeToString(hashByte);
        java.security.Signature signature = java.security.Signature.getInstance("SHA512withECDSA");
        signature.initSign(privateKey);
        signature.update(concatenated.getBytes());
        byte[] signatureByteArray = signature.sign();
        String encodedSig = Base64.getEncoder().encodeToString(signatureByteArray);

        return encodedSig;
    }
}