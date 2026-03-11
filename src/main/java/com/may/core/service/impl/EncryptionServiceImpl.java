package com.may.core.service.impl;

import cn.hutool.crypto.digest.BCrypt;
import com.may.core.EncryptionToolProperties;
import com.may.core.exception.EncryptionException;
import com.may.core.service.EncryptionService;
import com.may.core.util.SecretKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;

public class EncryptionServiceImpl implements EncryptionService {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String RSA_ALGORITHM = "RSA";
    private static final String ECIES_ALGORITHM = "ECIES";
    private static final String EC_ALGORITHM = "EC";
    private static final String SM4_ALGORITHM = "SM4/GCM/NoPadding";
    private static final String SM2_ALGORITHM = "SM2";
    private static final String SM3_ALGORITHM = "SM3";
    private static final int SM4_IV_LENGTH = 16;
    private static final int SM4_TAG_LENGTH = 128;

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
        validateInput(str, "BCrypt");
        try {
            String salt = properties.getBCryptSalt();
            return BCrypt.hashpw(str, Objects.isNull(salt) ? BCrypt.gensalt() : salt);
        } catch (Exception e) {
            throw new EncryptionException("BCrypt加密失敗：與Salt值的版本或格式不匹配", e);
        }
    }

    @Override
    public Boolean matchByBCrypt(String str, String encodeStr) {
        validateInput(str, "BCrypt");
        validateInput(encodeStr, "BCrypt");
        if (Objects.isNull(encodeStr) || encodeStr.isEmpty()) {
            throw new EncryptionException("BCrypt密文不能為空");
        }
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
        validateInput(plaintext, "AES");
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
        validateInput(ciphertext, "AES");
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

    // ==================== SM4 (GCM) ====================

    @Override
    public String encryptBySM4(String keyValue, String str) {
        return doSM4Encrypt(SecretKeyUtil.convertSM4Key(keyValue), str);
    }

    @Override
    public String encryptBySM4(String str) {
        String key = properties.getSM4SecretKey();
        if (key == null || key.isEmpty()) {
            throw new EncryptionException("未配置SM4密鑰，請在配置文件中設置 encryption.tool.SM4SecretKey");
        }
        return doSM4Encrypt(SecretKeyUtil.convertSM4Key(key), str);
    }

    @Override
    public String decryptBySM4(String keyValue, String str) {
        return doSM4Decrypt(SecretKeyUtil.convertSM4Key(keyValue), str);
    }

    @Override
    public String decryptBySM4(String str) {
        String key = properties.getSM4SecretKey();
        if (key == null || key.isEmpty()) {
            throw new EncryptionException("未配置SM4密鑰，請在配置文件中設置 encryption.tool.SM4SecretKey");
        }
        return doSM4Decrypt(SecretKeyUtil.convertSM4Key(key), str);
    }

    private String doSM4Encrypt(SecretKey secretKey, String plaintext) {
        validateInput(plaintext, "SM4");
        try {
            byte[] iv = new byte[SM4_IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(SM4_ALGORITHM, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

            byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);

            return Base64.getEncoder().encodeToString(byteBuffer.array());
        } catch (InvalidKeyException e) {
            throw new EncryptionException("SM4密鑰格式錯誤", e);
        } catch (Exception e) {
            throw new EncryptionException("SM4加密失敗", e);
        }
    }

    private String doSM4Decrypt(SecretKey secretKey, String ciphertext) {
        validateInput(ciphertext, "SM4");
        try {
            byte[] decoded = Base64.getDecoder().decode(ciphertext);

            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[SM4_IV_LENGTH];
            byteBuffer.get(iv);
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(SM4_ALGORITHM, "BC");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("SM4密鑰格式錯誤", e);
        } catch (Exception e) {
            throw new EncryptionException("SM4解密失敗", e);
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
        validateInput(plaintext, "RSA");
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
        validateInput(ciphertext, "RSA");
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
        if (publicKey == null || publicKey.isEmpty()) {
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
        if (privateKey == null || privateKey.isEmpty()) {
            throw new EncryptionException("未配置ECC私鑰");
        }
        return doECCDecrypt(privateKey, encryptedStr);
    }

    @Override
    public String decryptByECC(String privateKey, String encryptedStr) {
        return doECCDecrypt(privateKey, encryptedStr);
    }

    private String doECCEncrypt(String publicKeyStr, String plaintext) {
        validateInput(plaintext, "ECC");
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
        validateInput(ciphertext, "ECC");
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

    // ==================== SM2 ====================

    @Override
    public String encryptBySM2(String publicKey, String str) {
        return doSM2Encrypt(SecretKeyUtil.convertSM2PublicKey(publicKey), str);
    }

    @Override
    public String encryptBySM2(String str) {
        String publicKey = properties.getSM2PublicKey();
        if (publicKey == null || publicKey.isEmpty()) {
            throw new EncryptionException("未配置SM2公鑰，請在配置文件中設置 encryption.tool.SM2PublicKey");
        }
        return doSM2Encrypt(SecretKeyUtil.convertSM2PublicKey(publicKey), str);
    }

    @Override
    public String decryptBySM2(String privateKey, String encryptedStr) {
        return doSM2Decrypt(SecretKeyUtil.convertSM2PrivateKey(privateKey), encryptedStr);
    }

    @Override
    public String decryptBySM2(String encryptedStr) {
        String privateKey = properties.getSM2PrivateKey();
        if (privateKey == null || privateKey.isEmpty()) {
            throw new EncryptionException("未配置SM2私鑰，請在配置文件中設置 encryption.tool.SM2PrivateKey");
        }
        return doSM2Decrypt(SecretKeyUtil.convertSM2PrivateKey(privateKey), encryptedStr);
    }

    private String doSM2Encrypt(PublicKey publicKey, String plaintext) {
        validateInput(plaintext, "SM2");
        try {
            Cipher cipher = Cipher.getInstance(SM2_ALGORITHM, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("SM2公鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("SM2加密失敗", e);
        }
    }

    private String doSM2Decrypt(PrivateKey privateKey, String ciphertext) {
        validateInput(ciphertext, "SM2");
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
            Cipher cipher = Cipher.getInstance(SM2_ALGORITHM, "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("SM2私鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("SM2解密失敗", e);
        }
    }

    // ==================== Hash (SHA / MD5) ====================

    @Override
    public String encryptSHA1(String str) {
        return doHash("SHA-1", str, null);
    }

    @Override
    public Boolean verifySHA1(String encryptedStr, String str) {
        return verifyHash("SHA-1", encryptedStr, str, null);
    }

    @Override
    public String encryptSHA256(String str) {
        return doHash("SHA-256", str, null);
    }

    @Override
    public Boolean verifySHA256(String encryptedStr, String str) {
        return verifyHash("SHA-256", encryptedStr, str, null);
    }

    @Override
    public String encryptSHA512(String str) {
        return doHash("SHA-512", str, null);
    }

    @Override
    public Boolean verifySHA512(String encryptedStr, String str) {
        return verifyHash("SHA-512", encryptedStr, str, null);
    }

    @Override
    public String encryptSM3(String str) {
        return doHash(SM3_ALGORITHM, str, null);
    }

    @Override
    public Boolean verifySM3(String encryptedStr, String str) {
        return verifyHash(SM3_ALGORITHM, encryptedStr, str, null);
    }

    @Override
    public String encryptMD5(String str) {
        return doHash("MD5", str, null);
    }

    @Override
    public Boolean verifyMD5(String encryptedStr, String str) {
        return verifyHash("MD5", encryptedStr, str, null);
    }

    @Override
    public String hash(String algorithm, String str, String salt) {
        return doHash(algorithm, str, salt);
    }

    @Override
    public Boolean verifyHash(String algorithm, String encryptedStr, String str, String salt) {
        return doHash(algorithm, str, salt).equalsIgnoreCase(encryptedStr);
    }

    private String doHash(String algorithm, String str, String salt) {
        validateInput(str, algorithm);
        try {
            String dataToHash = (salt == null || salt.isEmpty()) ? str : str + salt;
            MessageDigest md = MessageDigest.getInstance(algorithm.toUpperCase(Locale.ROOT));
            byte[] hash = md.digest(dataToHash.getBytes(StandardCharsets.UTF_8));
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

    // ==================== 驗證工具 ====================

    private void validateInput(String input, String algorithm) {
        if (input == null || input.isEmpty()) {
            throw new EncryptionException(algorithm + "輸入不能為空");
        }
    }

    // ==================== 数字签名 - RSA ====================

    private static final String RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String ECDSA_SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String EDDSA_SIGNATURE_ALGORITHM = "EdDSA";

    @Override
    public String signByRSA(String privateKey, String data) {
        return doRSASign(privateKey, data);
    }

    @Override
    public String signByRSA(String data) {
        String privateKey = properties.getRSAPrivateKey();
        if (privateKey == null || privateKey.isEmpty()) {
            throw new EncryptionException("未配置RSA私鑰，請在配置文件中設置 encryption.tool.RSAPrivateKey");
        }
        return doRSASign(privateKey, data);
    }

    private String doRSASign(String privateKeyStr, String data) {
        validateInput(data, "RSA签名");
        try {
            PrivateKey privateKey = decodeRSAPrivateKey(privateKeyStr);
            Signature signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signBytes);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("RSA私鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("RSA簽名失敗", e);
        }
    }

    @Override
    public Boolean verifyByRSA(String publicKey, String data, String signature) {
        return doRSAVerify(publicKey, data, signature);
    }

    @Override
    public Boolean verifyByRSA(String data, String signature) {
        String publicKey = properties.getRSAPublicKey();
        if (publicKey == null || publicKey.isEmpty()) {
            throw new EncryptionException("未配置RSA公鑰，請在配置文件中設置 encryption.tool.RSAPublicKey");
        }
        return doRSAVerify(publicKey, data, signature);
    }

    private Boolean doRSAVerify(String publicKeyStr, String data, String signatureStr) {
        validateInput(data, "RSA验签");
        validateInput(signatureStr, "RSA签名");
        try {
            PublicKey publicKey = decodeRSAPublicKey(publicKeyStr);
            Signature signature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
            return signature.verify(signatureBytes);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("RSA公鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("RSA驗簽失敗", e);
        }
    }

    // ==================== 数字签名 - ECC ====================

    @Override
    public String signByECC(String privateKey, String data) {
        return doECCSign(privateKey, data);
    }

    @Override
    public String signByECC(String data) {
        String privateKey = properties.getECCPrivateKey();
        if (privateKey == null || privateKey.isEmpty()) {
            throw new EncryptionException("未配置ECC私鑰，請在配置文件中設置 encryption.tool.ECCPrivateKey");
        }
        return doECCSign(privateKey, data);
    }

    private String doECCSign(String privateKeyStr, String data) {
        validateInput(data, "ECC签名");
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Signature signature = Signature.getInstance(ECDSA_SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signBytes);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("ECC私鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("ECC簽名失敗", e);
        }
    }

    @Override
    public Boolean verifyByECC(String publicKey, String data, String signature) {
        return doECCVerify(publicKey, data, signature);
    }

    @Override
    public Boolean verifyByECC(String data, String signature) {
        String publicKey = properties.getECCPublicKey();
        if (publicKey == null || publicKey.isEmpty()) {
            throw new EncryptionException("未配置ECC公鑰，請在配置文件中設置 encryption.tool.ECCPublicKey");
        }
        return doECCVerify(publicKey, data, signature);
    }

    private Boolean doECCVerify(String publicKeyStr, String data, String signatureStr) {
        validateInput(data, "ECC验签");
        validateInput(signatureStr, "ECC签名");
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Signature signature = Signature.getInstance(ECDSA_SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signatureStr);
            return signature.verify(signatureBytes);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("ECC公鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("ECC驗簽失敗", e);
        }
    }

    // ==================== 数字签名 - EdDSA ====================

    @Override
    public String signByEdDSA(String privateKey, String data) {
        validateInput(data, "EdDSA签名");
        validateInput(privateKey, "EdDSA私钥");
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(EDDSA_SIGNATURE_ALGORITHM);
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            Signature signature = Signature.getInstance(EDDSA_SIGNATURE_ALGORITHM);
            signature.initSign(privKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signBytes);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("EdDSA私鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("EdDSA簽名失敗", e);
        }
    }

    @Override
    public Boolean verifyByEdDSA(String publicKey, String data, String signature) {
        validateInput(data, "EdDSA验签");
        validateInput(signature, "EdDSA签名");
        validateInput(publicKey, "EdDSA公钥");
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(EDDSA_SIGNATURE_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);

            Signature sig = Signature.getInstance(EDDSA_SIGNATURE_ALGORITHM);
            sig.initVerify(pubKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return sig.verify(signatureBytes);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("EdDSA公鑰無效", e);
        } catch (Exception e) {
            throw new EncryptionException("EdDSA驗簽失敗", e);
        }
    }

    // ==================== PBKDF2 密钥派生 ====================

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int DEFAULT_PBKDF2_ITERATIONS = 100000;
    private static final int DEFAULT_PBKDF2_KEY_LENGTH = 32;

    @Override
    public String deriveKeyByPBKDF2(String password, String salt, int iterations, int keyLength) {
        validateInput(password, "PBKDF2");
        validateInput(salt, "PBKDF2盐值");
        if (iterations <= 0) {
            throw new EncryptionException("PBKDF2迭代次數必須大於0");
        }
        if (keyLength <= 0) {
            throw new EncryptionException("PBKDF2密鑰長度必須大於0");
        }
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), iterations, keyLength * 8);
            byte[] key = keyFactory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(key);
        } catch (Exception e) {
            throw new EncryptionException("PBKDF2密鑰派生失敗", e);
        }
    }

    @Override
    public String deriveKeyByPBKDF2(String password, String salt) {
        return deriveKeyByPBKDF2(password, salt, DEFAULT_PBKDF2_ITERATIONS, DEFAULT_PBKDF2_KEY_LENGTH);
    }

    // ==================== 密钥指纹 ====================

    @Override
    public String getPublicKeyFingerprint(String publicKey) {
        validateInput(publicKey, "公钥指纹");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(keyBytes);
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new EncryptionException("公鑰指紋生成失敗", e);
        }
    }

    // ==================== 额外哈希算法 ====================

    @Override
    public String encryptSHA224(String str) {
        return doHash("SHA-224", str, null);
    }

    @Override
    public Boolean verifySHA224(String encryptedStr, String str) {
        return verifyHash("SHA-224", encryptedStr, str, null);
    }

    @Override
    public String encryptSHA384(String str) {
        return doHash("SHA-384", str, null);
    }

    @Override
    public Boolean verifySHA384(String encryptedStr, String str) {
        return verifyHash("SHA-384", encryptedStr, str, null);
    }

    @Override
    public String encryptSHA3_256(String str) {
        return doHash("SHA3-256", str, null);
    }

    @Override
    public Boolean verifySHA3_256(String encryptedStr, String str) {
        return verifyHash("SHA3-256", encryptedStr, str, null);
    }

}