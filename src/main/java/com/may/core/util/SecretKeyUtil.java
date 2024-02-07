package com.may.core.util;

import com.may.core.domain.ECCSecretKey;
import com.may.core.domain.RSASecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 密码加密&校验工具类
 */
public class SecretKeyUtil {
    private SecretKeyUtil() {
    }

    /**
     * <!-- 生成随机AES密钥 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param bit 根据你的安全需求，你也可以选择生成128或192或256位的密钥
     * @return 随机AES密钥
     */
    public static String generateAESKey(int bit) throws NoSuchAlgorithmException {
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

        SecretKey secretKey = keyGenerator.generateKey();

        // 生成AES密钥
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * <!-- 将byte[]转换成SecretKey -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param keyMaterial 密钥的byte[]
     * @return AES密钥
     */
    public static SecretKey convertAESKey(String keyMaterial) {
        // 确保你的keyMaterial字节数组是对应算法要求的密钥长度
        byte[] key = Base64.getDecoder().decode(keyMaterial);
        try {
            return new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            throw new RuntimeException("确保你的AES密钥字节数组是对应算法要求的密钥长度");
        }
    }

    /**
     * <!-- 生成RSA公钥和私钥 -->
     *
     * <p>
     * RSA加密是一种公钥密码体制，它是目前应用最广泛的非对称加密算法之一。非对称加密意味着加密和解密使用两个不同的密钥，这两个密钥在数学上相关联，
     * 但不能从一个密钥直接推导出另一个密钥。
     *
     * @param keySize 密钥位数
     * @return 公钥及私钥
     */
    public static RSASecretKey generateRSAKey(Integer keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
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

        // 转换成字符串
        String publicKeyString = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        // 返回密钥对
        return RSASecretKey.builder()
                .publicKey(keyPair.getPublic())
                .publicKeyStr(publicKeyString)
                .privateKey(keyPair.getPrivate())
                .privateKeyStr(privateKeyString)
                .build();
    }

    /**
     * <!-- 生成ECC公钥和私钥 -->
     *
     * <p>
     * 椭圆曲线密码
     *
     * @param stdName 曲线参数
     * @return 公钥及私钥
     */
    public static ECCSecretKey generateECCKeyPair(String stdName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(stdName); // 指定曲线参数
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), PKCS8EncodedKeySpec.class);
        return ECCSecretKey.builder()
                .publicKey(keyPair.getPublic())
                .publicKeyStr(Base64.getEncoder().encodeToString(publicKeySpec.getEncoded()))
                .privateKey(keyPair.getPrivate())
                .privateKeyStr(Base64.getEncoder().encodeToString(privateKeySpec.getEncoded()))
                .build();
    }

}
