package org.plutos.one.util;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.plutos.one.model.EncryptedResponse;
import org.plutos.one.model.Signature;

import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.infrastructure.Infrastructure;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.crypto.Cipher;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class DigitalSignerDecryptor {

    private static final Logger log = LoggerFactory.getLogger(DigitalSignerDecryptor.class);

    @Inject
    CertificateLoader certificateLoader;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // public Uni<String> decrypt(EncryptedResponse encryptedResponse) {
    //     return Uni.createFrom().item(() -> {
    //         try {
    //             String decryptedJson = decryptPayload(encryptedResponse.getPayload(),
    //                     certificateLoader.getPlutosPrivateKeyObj());
    //             // log.debug("decryptedJson ===>\n" + decryptedJson);
    //             log.debug("Decrypted JSON: \n{}", decryptedJson);

    //             boolean verified = verifySignature(encryptedResponse.getSignature(),
    //                     certificateLoader.getIbmbPublicKeyObj(),
    //                     decryptedJson);

    //             if (!verified) {
    //                 throw new SecurityException("Signature verification failed");
    //             }

    //             return decryptedJson;
    //         } catch (Exception e) {
    //             throw new RuntimeException("Decryption failed", e);
    //         }
    //     }).runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
    // }


public Uni<String> decrypt(EncryptedResponse encryptedResponse) {
    return Uni.createFrom().item(() -> {
        try {

            if (encryptedResponse.getSignatures() == null ||
                encryptedResponse.getSignatures().isEmpty()) {
                throw new IllegalArgumentException("No signature found in request");
            }

            Signature signatureObj = encryptedResponse.getSignatures().get(0);

            String decryptedJson = decryptPayload(
                encryptedResponse.getPayload(),
                certificateLoader.getPlutosPrivateKeyObj()
            );

            log.debug("Decrypted JSON:\n{}", decryptedJson);

            boolean verified = verifySignature(
                signatureObj,
                certificateLoader.getIbmbPublicKeyObj(),
                decryptedJson
            );

            if (!verified) {
                throw new SecurityException("Signature verification failed");
            }

            return decryptedJson;

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }).runSubscriptionOn(Infrastructure.getDefaultWorkerPool());
}


    public static String decryptPayload(String cipherTextBase64, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ECIESwithSHA512/NONE/NoPadding");
        IESParameterSpec iesParamSpec = new IESParameterSpec(null, null, 256);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, iesParamSpec);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherTextBase64.getBytes())));
    }

    // public boolean verifySignature(Signature signatureObj, PublicKey publicKey, String json)
    //         throws Exception {

    //     String protectedHeader = new String(Base64.getDecoder().decode(signatureObj.getProtectedSignature()),
    //             StandardCharsets.UTF_8);

    //     long created = extractLong(protectedHeader, "created");
    //     long expires = extractLong(protectedHeader, "expires");

    //     long now = System.currentTimeMillis();
    //     if (now < created || now > expires) {
    //         log.error("Message expired or not yet valid.");
    //         return false;
    //     }

    //     byte[] signature = Base64.getDecoder().decode(signatureObj.getSignature().getBytes());
    //     Blake2bDigest blakeHash = new Blake2bDigest(512);
    //     blakeHash.update(json.getBytes(), 0, json.getBytes().length);
    //     byte[] hashByte = new byte[blakeHash.getDigestSize()];
    //     blakeHash.doFinal(hashByte, 0);
    //     String concatenated = "(created):" + created + "\n"
    //             + "(expires):" + expires + "\n" + "digest:BLAKE2b-512="
    //             + Base64.getEncoder().encodeToString(hashByte);

    //     java.security.Signature verifier = java.security.Signature.getInstance("SHA512withECDSA");
    //     verifier.initVerify(publicKey);
    //     verifier.update(concatenated.getBytes());
    //     return verifier.verify(signature);
    // }

public boolean verifySignature(Signature signatureObj, PublicKey publicKey, String json)
        throws Exception {

    // 🔐 Defensive checks
    if (signatureObj == null) {
        throw new IllegalArgumentException("Signature object is null");
    }
    if (signatureObj.getProtectedSignature() == null) {
        throw new IllegalArgumentException("Protected signature is missing");
    }
    if (signatureObj.getSignature() == null) {
        throw new IllegalArgumentException("Signature value is missing");
    }

    String protectedHeader = new String(
            Base64.getDecoder().decode(signatureObj.getProtectedSignature()),
            StandardCharsets.UTF_8
    );

    long created = extractLong(protectedHeader, "created");
    long expires = extractLong(protectedHeader, "expires");

    long now = System.currentTimeMillis();
    if (now < created || now > expires) {
        log.error("Message expired or not yet valid.");
        return false;
    }

    byte[] signatureBytes = Base64.getDecoder()
            .decode(signatureObj.getSignature());

    Blake2bDigest blakeHash = new Blake2bDigest(512);
    blakeHash.update(json.getBytes(StandardCharsets.UTF_8), 0, json.getBytes().length);
    byte[] hashByte = new byte[blakeHash.getDigestSize()];
    blakeHash.doFinal(hashByte, 0);

    String concatenated =
            "(created):" + created + "\n" +
            "(expires):" + expires + "\n" +
            "digest:BLAKE2b-512=" + Base64.getEncoder().encodeToString(hashByte);

    java.security.Signature verifier =
            java.security.Signature.getInstance("SHA512withECDSA");

    verifier.initVerify(publicKey);
    verifier.update(concatenated.getBytes(StandardCharsets.UTF_8));

    return verifier.verify(signatureBytes);
}



    private long extractLong(String input, String key) {
        String match = input.replaceAll(".*" + key + "=\\\"(\\d+)\\\".*", "$1");
        return Long.parseLong(match);
    }
}