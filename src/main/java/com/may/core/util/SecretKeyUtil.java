package com.may.core.util;

import com.may.core.domain.ECCSecretKey;
import com.may.core.domain.RSASecretKey;
import com.may.core.domain.SM2SecretKey;
import com.may.core.exception.EncryptionException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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

    // ==================== 密鑰生成 ====================

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
     * <!-- 生成隨機SM4密鑰 -->
     *
     * @return Base64 編碼的 SM4 密鑰
     */
    public static String generateSM4Key() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", "BC");
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            keyGenerator.init(128, secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EncryptionException("SM4演算法在當前環境中不可用", e);
        } catch (Exception e) {
            throw new EncryptionException("SM4密鑰生成失敗", e);
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

    /**
     * <!-- 生成SM2公鑰和私鑰 -->
     *
     * @return SM2 密鑰對
     */
    public static SM2SecretKey generateSM2KeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2", "BC");
            KeyFactory keyFactory = KeyFactory.getInstance("SM2");
            
            // 使用默认曲线 sm2p256v1
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("sm2p256v1");
            keyPairGenerator.initialize(ecSpec, new SecureRandom());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            X509EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
            PKCS8EncodedKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);

            return SM2SecretKey.builder()
                    .publicKey(keyPair.getPublic())
                    .publicKeyStr(Base64.getEncoder().encodeToString(publicKeySpec.getEncoded()))
                    .privateKey(keyPair.getPrivate())
                    .privateKeyStr(Base64.getEncoder().encodeToString(privateKeySpec.getEncoded()))
                    .build();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EncryptionException("SM2演算法或BC Provider在當前環境中不可用", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("SM2曲線參數無效", e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("SM2密鑰規範無效", e);
        }
    }

    // ==================== 密鑰轉換 ====================

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
     * <!-- 將 Base64 字串轉換為 SM4 SecretKey -->
     *
     * @param keyMaterial Base64 編碼的 SM4 密鑰字串
     * @return SM4 SecretKey
     */
    public static SecretKey convertSM4Key(String keyMaterial) {
        try {
            byte[] key = Base64.getDecoder().decode(keyMaterial);
            if (key.length != 16) {
                throw new EncryptionException("SM4密鑰長度必須為16字節");
            }
            return new SecretKeySpec(key, "SM4");
        } catch (Exception e) {
            if (e instanceof EncryptionException) {
                throw (EncryptionException) e;
            }
            throw new EncryptionException("SM4密鑰格式無效，請確保密鑰為正確的Base64編碼", e);
        }
    }

    /**
     * <!-- 將 Base64 字串轉換為 SM2 PublicKey -->
     *
     * @param publicKeyStr Base64 編碼的 SM2 公鑰字串
     * @return SM2 PublicKey
     */
    public static PublicKey convertSM2PublicKey(String publicKeyStr) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return KeyFactory.getInstance("SM2", "BC").generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EncryptionException("SM2演算法在當前環境中不可用", e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("SM2公鑰格式無效", e);
        }
    }

    /**
     * <!-- 將 Base64 字串轉換為 SM2 PrivateKey -->
     *
     * @param privateKeyStr Base64 編碼的 SM2 私鑰字串
     * @return SM2 PrivateKey
     */
    public static PrivateKey convertSM2PrivateKey(String privateKeyStr) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return KeyFactory.getInstance("SM2", "BC").generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new EncryptionException("SM2演算法在當前環境中不可用", e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("SM2私鑰格式無效", e);
        }
    }

    // ==================== 編碼工具 ====================

    /**
     * <!-- 將字節數組轉換為16進制字符串 -->
     *
     * @param bytes 字節數組
     * @return 16進制字符串
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * <!-- 將16進制字符串轉換為字節數組 -->
     *
     * @param hex 16進制字符串
     * @return 字節數組
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) {
            throw new EncryptionException("無效的16進制字符串");
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * <!-- Base64 編碼 -->
     *
     * @param data 字節數組
     * @return Base64 編碼字符串
     */
    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * <!-- Base64 解碼 -->
     *
     * @param base64Str Base64 編碼字符串
     * @return 字節數組
     */
    public static byte[] base64Decode(String base64Str) {
        return Base64.getDecoder().decode(base64Str);
    }

}