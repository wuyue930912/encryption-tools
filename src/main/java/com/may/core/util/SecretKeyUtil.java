package com.may.core.util;

import com.may.core.domain.ECCSecretKey;
import com.may.core.domain.RSASecretKey;
import com.may.core.exception.EncryptionException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * 密鑰生成與轉換工具類
 */
public class SecretKeyUtil {

    private SecretKeyUtil() {
    }

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * <!-- 生成隨機AES密鑰 -->
     *
     * @param bit 密鑰位數，支持 128、192、256
     * @return Base64 編碼的 AES 密鑰
     */
    public static String generateAESKey(int bit) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            keyGenerator.init(bit, secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("AES演算法在當前環境中不可用", e);
        } catch (Exception e) {
            throw new EncryptionException("AES密鑰位數應為128、192或256", e);
        }
    }

    /**
     * <!-- 將 Base64 字串轉換為 SecretKey -->
     *
     * @param keyMaterial Base64 編碼的密鑰字串
     * @return AES SecretKey
     */
    public static SecretKey convertAESKey(String keyMaterial) {
        try {
            byte[] key = Base64.getDecoder().decode(keyMaterial);
            return new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            throw new EncryptionException("AES密鑰格式無效，請確保密鑰為正確的Base64編碼", e);
        }
    }

    /**
     * <!-- 生成RSA公鑰和私鑰 -->
     *
     * @param keySize 密鑰位數（建議 2048 以上）
     * @return RSA 密鑰對
     */
    public static RSASecretKey generateRSAKey(Integer keySize) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4);
            keyPairGenerator.initialize(spec);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            return RSASecretKey.builder()
                    .publicKey(keyPair.getPublic())
                    .publicKeyStr(publicKeyString)
                    .privateKey(keyPair.getPrivate())
                    .privateKeyStr(privateKeyString)
                    .build();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EncryptionException("RSA演算法或BC Provider在當前環境中不可用", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("RSA密鑰參數無效", e);
        }
    }

    /**
     * <!-- 生成ECC公鑰和私鑰 -->
     *
     * @param stdName 曲線參數（如 secp256k1、secp256r1）
     * @return ECC 密鑰對
     */
    public static ECCSecretKey generateECCKeyPair(String stdName) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(stdName);
            keyPairGenerator.initialize(ecSpec);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            X509EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
            PKCS8EncodedKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);

            return ECCSecretKey.builder()
                    .publicKey(keyPair.getPublic())
                    .publicKeyStr(Base64.getEncoder().encodeToString(publicKeySpec.getEncoded()))
                    .privateKey(keyPair.getPrivate())
                    .privateKeyStr(Base64.getEncoder().encodeToString(privateKeySpec.getEncoded()))
                    .build();
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("EC演算法在當前環境中不可用", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("ECC曲線參數無效：" + stdName, e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("ECC密鑰規範無效", e);
        }
    }

}
