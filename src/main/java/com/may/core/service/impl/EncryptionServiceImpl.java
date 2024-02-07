package com.may.core.service.impl;

import cn.hutool.crypto.digest.BCrypt;
import com.may.core.EncryptionToolProperties;
import com.may.core.domain.RSASecretKey;
import com.may.core.service.EncryptionService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
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
    public SecretKey generateAESKey(int bit) throws NoSuchAlgorithmException {
        // 实例化KeyGenerator对象，指定算法为AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

        // 强制使用新的安全随机数源（可选）
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();

        // 指定密钥长度为128位（AES标准支持128、192和256位）
        try {
            keyGenerator.init(bit, secureRandom);
        } catch (Exception e) {
            throw new RuntimeException("AES密钥位数应为128或192或256");
        }

        // 生成AES密钥
        return keyGenerator.generateKey();
    }

    @Override
    public SecretKey convertAESKey(byte[] keyMaterial) {
        // 确保你的keyMaterial字节数组是对应算法要求的密钥长度
        try {
            return new SecretKeySpec(keyMaterial, "AES");
        } catch (Exception e) {
            throw new RuntimeException("确保你的AES密钥字节数组是对应算法要求的密钥长度");
        }
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
            cipher.init(Cipher.ENCRYPT_MODE, convertAESKey(properties.getAESSecretKey()));
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
            cipher.init(Cipher.DECRYPT_MODE, convertAESKey(properties.getAESSecretKey()));
        } catch (InvalidKeyException e) {
            throw new RuntimeException("AES密钥格式错误");
        }
        byte[] decryptedData = cipher.doFinal(bytes);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    @Override
    public RSASecretKey generateRSAKey(Integer keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // 添加Bouncy Castle作为安全提供者
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // 指定算法为RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");

        // 设置密钥长度，例如2048位
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4);

        // 初始化密钥生成器
        keyPairGenerator.initialize(spec);

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 返回密钥对
        return RSASecretKey.builder()
                .publicKey(keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .build();
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
        byte[] publicKeyBytes = properties.getRSAPublicKey();
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
    public String decryptByRSA(byte[] encryptedBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // 从使用者配置文件中获取私钥byte[]
        byte[] privateKeyBytes = properties.getRSAPrivateKey();
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
}