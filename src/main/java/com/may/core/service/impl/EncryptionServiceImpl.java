package com.may.core.service.impl;

import cn.hutool.crypto.digest.BCrypt;
import com.may.core.EncryptionToolProperties;
import com.may.core.service.EncryptionService;
import com.may.core.util.SecretKeyUtil;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    private final EncryptionToolProperties properties;

    public EncryptionServiceImpl(EncryptionToolProperties properties) {
        this.properties = properties;
    }

    @Override
    public String encryptByBCrypt(String str) {
        try {
            String salt = properties.getBCryptSalt();
            return BCrypt.hashpw(str, Objects.isNull(salt) ? BCrypt.gensalt() : salt);
        } catch (Exception e) {
            throw new RuntimeException("与Salt值的版本或格式不匹配");
        }
    }

    @Override
    public Boolean matchByBCrypt(String str, String encodeStr) {
        return BCrypt.checkpw(str, encodeStr);
    }

    @Override
    public String encryptByAES(String keyValue, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyUtil.convertAESKey(keyValue));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] encryptBytes = cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    @Override
    public String encryptByAES(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyUtil.convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] encryptBytes = cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    @Override
    public String decryptByAES(String keyValue, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        // 解密过程
        try {
            cipher.init(Cipher.DECRYPT_MODE, SecretKeyUtil.convertAESKey(keyValue));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(str));
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public String decryptByAES(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        // 解密过程
        try {
            cipher.init(Cipher.DECRYPT_MODE, SecretKeyUtil.convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(str));
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public String encryptByRSA(String publicKeyStr, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        byte[] plaintextBytes = str.getBytes();
        Cipher encryptCipher = Cipher.getInstance("RSA");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptBytes =  encryptCipher.doFinal(plaintextBytes);
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    @Override
    public String encryptByRSA(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        // 从使用者配置文件中获取公钥byte[]
        byte[] publicKeyBytes = Base64.getDecoder().decode(properties.getRSAPublicKey());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        byte[] plaintextBytes = str.getBytes();
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptBytes =  encryptCipher.doFinal(plaintextBytes);
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    private String decrypt(byte[] encryptedBytes, KeyFactory keyFactory, byte[] privateKeyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey realKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, realKey);
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    @Override
    public String decryptByRSA(String privateKey, String encryptedStr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedStr);
        return decrypt(encryptedBytes, keyFactory, privateKeyBytes);
    }

    @Override
    public String decryptByRSA(String encryptedStr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // 从使用者配置文件中获取私钥byte[]
        byte[] privateKeyBytes = Base64.getDecoder().decode(properties.getRSAPrivateKey());
        Cipher decryptCipher = Cipher.getInstance("RSA");
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedStr);

        // 将byte[]转换成PrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey;
        try {
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        // 通过私钥解密数据
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    @Override
    public String encryptByECC(String str) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String publicKey = properties.getECCPublicKey();
        if (Objects.isNull(publicKey)) {
            throw new RuntimeException("未配置ECC公钥");
        }
        return getECCEncryptResult(str, publicKey);
    }

    @Override
    public String encryptByECC(String publicKey, String str) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return getECCEncryptResult(str, publicKey);
    }

    @Override
    public String decryptByECC(String encryptedStr) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String privateKey = properties.getECCPrivateKey();
        if (Objects.isNull(privateKey)) {
            throw new RuntimeException("未配置ECC私钥");
        }
        return getECCDecryptResult(privateKey, encryptedStr);
    }

    @Override
    public String decryptByECC(String privateKey, String encryptedStr) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        return getECCDecryptResult(privateKey, encryptedStr);
    }

    private String getECCDecryptResult(String privateKey, String encryptedStr) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey key = keyFactory.generatePrivate(privateKeySpec);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedStr);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }


    private String getECCEncryptResult(String str, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PublicKey key = keyFactory.generatePublic(publicKeySpec);
        Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(str.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
