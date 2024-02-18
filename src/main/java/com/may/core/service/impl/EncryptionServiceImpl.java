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
    public String encryptByAES(String keyValue, String str) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("请求的填充方式在当前环境中不可用");
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyUtil.convertAESKey(keyValue));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        return getEncryptResult(str, cipher);
    }

    private String getEncryptResult(String str, Cipher cipher) {
        byte[] encryptBytes;
        try {
            encryptBytes = cipher.doFinal(str.getBytes(StandardCharsets.UTF_8));
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("加密操作中的数据块大小无效");
        } catch (BadPaddingException e) {
            throw new RuntimeException("解密过程中发生了错误的填充");
        }
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    @Override
    public String encryptByAES(String str) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("请求的填充方式在当前环境中不可用");
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyUtil.convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        return getEncryptResult(str, cipher);
    }

    @Override
    public String decryptByAES(String keyValue, String str) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("请求的填充方式在当前环境中不可用");
        }
        // 解密过程
        try {
            cipher.init(Cipher.DECRYPT_MODE, SecretKeyUtil.convertAESKey(keyValue));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        return getDecryptData(str, cipher);
    }

    private String getDecryptData(String str, Cipher cipher) {
        byte[] decryptedData;
        try {
            decryptedData = cipher.doFinal(Base64.getDecoder().decode(str));
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("加密操作中的数据块大小无效");
        } catch (BadPaddingException e) {
            throw new RuntimeException("解密过程中发生了错误的填充");
        }
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public String decryptByAES(String str) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("请求的填充方式在当前环境中不可用");
        }
        // 解密过程
        try {
            cipher.init(Cipher.DECRYPT_MODE, SecretKeyUtil.convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        return getDecryptData(str, cipher);
    }

    @Override
    public String encryptByRSA(String publicKeyStr, String str) {
        byte[] plaintextBytes = str.getBytes();
        Cipher encryptCipher;
        KeyFactory keyFactory;
        try {
            encryptCipher = Cipher.getInstance("RSA");
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("请求的填充方式在当前环境中不可用");
        }
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey;
        try {
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("密钥规范无效或不受支持");
        }
        try {
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("无效或不支持的密钥");
        }
        byte[] encryptBytes;
        try {
            encryptBytes = encryptCipher.doFinal(plaintextBytes);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("加密操作中的数据块大小无效");
        } catch (BadPaddingException e) {
            throw new RuntimeException("解密过程中发生了错误的填充");
        }
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    @Override
    public String encryptByRSA(String str) {
        // 从使用者配置文件中获取公钥byte[]
        byte[] publicKeyBytes = Base64.getDecoder().decode(properties.getRSAPublicKey());
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        }
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey;
        try {
            publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("密钥规范无效或不受支持");
        }
        byte[] plaintextBytes = str.getBytes();
        Cipher encryptCipher;
        try {
            encryptCipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("请求的加密算法或哈希算法在当前环境中不可用");
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("请求的填充方式在当前环境中不可用");
        }
        try {
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("无效或不支持的密钥");
        }
        byte[] encryptBytes;
        try {
            encryptBytes = encryptCipher.doFinal(plaintextBytes);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException("加密操作中的数据块大小无效");
        } catch (BadPaddingException e) {
            throw new RuntimeException("解密过程中发生了错误的填充");
        }
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
