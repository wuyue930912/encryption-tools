package com.may.core.service.impl;

import cn.hutool.crypto.digest.BCrypt;
import com.may.core.EncryptionToolProperties;
import com.may.core.exception.EncryptionException;
import com.may.core.service.EncryptionService;
import com.may.core.util.SecretKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public class EncryptionServiceImpl implements EncryptionService {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String ECIES_ALGORITHM = "ECIES";
    private static final String EC_ALGORITHM = "EC";

    private final EncryptionToolProperties properties;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public EncryptionServiceImpl(EncryptionToolProperties properties) {
        this.properties = properties;
    }

    // ==================== BCrypt ====================

    @Override
    public String encryptByBCrypt(String str) {
        try {
            String salt = properties.getBCryptSalt();
            return BCrypt.hashpw(str, Objects.isNull(salt) ? BCrypt.gensalt() : salt);
        } catch (Exception e) {
            throw new EncryptionException("BCrypt加密失敗：與Salt值的版本或格式不匹配", e);
        }
    }

    @Override
    public Boolean matchByBCrypt(String str, String encodeStr) {
        return BCrypt.checkpw(str, encodeStr);
    }

    // ==================== AES (GCM) ====================

    @Override
    public String encryptByAES(String keyValue, String str) {
        return doAESEncrypt(SecretKeyUtil.convertAESKey(keyValue), str);
    }

    @Override
    public String encryptByAES(String str) {
        return doAESEncrypt(SecretKeyUtil.convertAESKey(properties.getAESSecretKey()), str);
    }

    @Override
    public String decryptByAES(String keyValue, String str) {
        return doAESDecrypt(SecretKeyUtil.convertAESKey(keyValue), str);
    }

    @Override
    public String decryptByAES(String str) {
        return doAESDecrypt(SecretKeyUtil.convertAESKey(properties.getAESSecretKey()), str);
    }

    private String doAESEncrypt(SecretKey secretKey, String plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);

            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (InvalidKeyException e) {
            throw new EncryptionException("AES密鑰格式錯誤", e);
        } catch (Exception e) {
            throw new EncryptionException("AES加密失敗", e);
        }
    }

    private String doAESDecrypt(SecretKey secretKey, String ciphertext) {
        try {
            byte[] decoded = Base64.getDecoder().decode(ciphertext);

            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[GCM_IV_LENGTH];
            byteBuffer.get(iv);
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("AES密鑰格式錯誤", e);
        } catch (Exception e) {
            throw new EncryptionException("AES解密失敗", e);
        }
    }

    // ==================== RSA ====================

    @Override
    public String encryptByRSA(String publicKeyStr, String str) {
        PublicKey publicKey = decodeRSAPublicKey(publicKeyStr);
        return doRSAEncrypt(publicKey, str);
    }

    @Override
    public String encryptByRSA(String str) {
        PublicKey publicKey = decodeRSAPublicKey(properties.getRSAPublicKey());
        return doRSAEncrypt(publicKey, str);
    }

    @Override
    public String decryptByRSA(String privateKeyStr, String encryptedStr) {
        PrivateKey privateKey = decodeRSAPrivateKey(privateKeyStr);
        return doRSADecrypt(privateKey, encryptedStr);
    }

    @Override
    public String decryptByRSA(String encryptedStr) {
        PrivateKey privateKey = decodeRSAPrivateKey(properties.getRSAPrivateKey());
        return doRSADecrypt(privateKey, encryptedStr);
    }

    private PublicKey decodeRSAPublicKey(String publicKeyStr) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("RSA演算法在當前環境中不可用", e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("RSA公鑰規範無效或不受支持", e);
        }
    }

    private PrivateKey decodeRSAPrivateKey(String privateKeyStr) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return KeyFactory.getInstance(RSA_ALGORITHM).generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("RSA演算法在當前環境中不可用", e);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("RSA私鑰規範無效或不受支持", e);
        }
    }

    private String doRSAEncrypt(PublicKey publicKey, String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("RSA公鑰無效", e);
        } catch (IllegalBlockSizeException e) {
            throw new EncryptionException("RSA加密數據塊大小無效", e);
        } catch (BadPaddingException e) {
            throw new EncryptionException("RSA加密填充錯誤", e);
        } catch (Exception e) {
            throw new EncryptionException("RSA加密失敗", e);
        }
    }

    private String doRSADecrypt(PrivateKey privateKey, String ciphertext) {
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("RSA私鑰無效", e);
        } catch (IllegalBlockSizeException e) {
            throw new EncryptionException("RSA解密數據塊大小無效", e);
        } catch (BadPaddingException e) {
            throw new EncryptionException("RSA解密填充錯誤", e);
        } catch (Exception e) {
            throw new EncryptionException("RSA解密失敗", e);
        }
    }

    // ==================== ECC (ECIES) ====================

    @Override
    public String encryptByECC(String str) {
        String publicKey = properties.getECCPublicKey();
        if (Objects.isNull(publicKey)) {
            throw new EncryptionException("未配置ECC公鑰");
        }
        return doECCEncrypt(publicKey, str);
    }

    @Override
    public String encryptByECC(String publicKey, String str) {
        return doECCEncrypt(publicKey, str);
    }

    @Override
    public String decryptByECC(String encryptedStr) {
        String privateKey = properties.getECCPrivateKey();
        if (Objects.isNull(privateKey)) {
            throw new EncryptionException("未配置ECC私鑰");
        }
        return doECCDecrypt(privateKey, encryptedStr);
    }

    @Override
    public String decryptByECC(String privateKey, String encryptedStr) {
        return doECCDecrypt(privateKey, encryptedStr);
    }

    private String doECCEncrypt(String publicKeyStr, String plaintext) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance(ECIES_ALGORITHM, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("ECC公鑰規範無效或不受支持", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("ECC公鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("ECC加密失敗", e);
        }
    }

    private String doECCDecrypt(String privateKeyStr, String ciphertext) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher cipher = Cipher.getInstance(ECIES_ALGORITHM, "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (InvalidKeySpecException e) {
            throw new EncryptionException("ECC私鑰規範無效或不受支持", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("ECC私鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("ECC解密失敗", e);
        }
    }

    // ==================== Hash (SHA / MD5) ====================

    @Override
    public String encryptSHA1(String str) {
        return doHash("SHA-1", str);
    }

    @Override
    public Boolean verifySHA1(String encryptedStr, String str) {
        return encryptSHA1(str).equals(encryptedStr);
    }

    @Override
    public String encryptSHA256(String str) {
        return doHash("SHA-256", str);
    }

    @Override
    public Boolean verifySHA256(String encryptedStr, String str) {
        return encryptSHA256(str).equals(encryptedStr);
    }

    @Override
    public String encryptSHA512(String str) {
        return doHash("SHA-512", str);
    }

    @Override
    public Boolean verifySHA512(String encryptedStr, String str) {
        return encryptSHA512(str).equals(encryptedStr);
    }

    @Override
    public String encryptMD5(String str) {
        return doHash("MD5", str);
    }

    @Override
    public Boolean verifyMD5(String encryptedStr, String str) {
        return encryptMD5(str).equals(encryptedStr);
    }

    private String doHash(String algorithm, String str) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hash = md.digest(str.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException(algorithm + "演算法在當前環境中不可用", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

}
