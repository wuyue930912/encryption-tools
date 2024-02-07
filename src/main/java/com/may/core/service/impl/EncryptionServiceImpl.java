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
    public byte[] encryptByAES(SecretKey keyValue, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, keyValue);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        return cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] encryptByAES(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyUtil.convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        return cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String decryptByAES(SecretKey keyValue, byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        // 解密过程
        try {
            cipher.init(Cipher.DECRYPT_MODE, keyValue);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] decryptedData = cipher.doFinal(bytes);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public String decryptByAES(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        // 解密过程
        try {
            cipher.init(Cipher.DECRYPT_MODE, SecretKeyUtil.convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] decryptedData = cipher.doFinal(bytes);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] encryptByRSA(PublicKey publicKey, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] plaintextBytes = str.getBytes();
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(plaintextBytes);
    }

    @Override
    public byte[] encryptByRSA(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        // 从使用者配置文件中获取公钥byte[]
        byte[] publicKeyBytes = Base64.getDecoder().decode(properties.getRSAPublicKey());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        byte[] plaintextBytes = str.getBytes();
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(plaintextBytes);
    }

    @Override
    public String decryptByRSA(PrivateKey privateKey, byte[] encryptedBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    @Override
    public String decryptByRSA(PrivateKey privateKey, String encryptedStr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedStr);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    @Override
    public String decryptByRSA(String privateKey, byte[] encryptedBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
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
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey realKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, realKey);
        byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    @Override
    public String decryptByRSA(byte[] encryptedBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // 从使用者配置文件中获取私钥byte[]
        byte[] privateKeyBytes = Base64.getDecoder().decode(properties.getRSAPrivateKey());
        Cipher decryptCipher = Cipher.getInstance("RSA");

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
}
