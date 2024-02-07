package com.may.core.service;

import com.may.core.domain.RSASecretKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public interface EncryptionService {

    /**
     * <!-- 使用BCrypt算法加密字符串 -->
     * <p>
     * BCrypt算法是一种强大的密码哈希函数，由Niels Provos和David Mazières在1999年设计，
     * 旨在为基于密码的身份验证提供安全散列。它基于Blowfish加密算法的变体，
     * 并结合了几个关键的安全特性来增强对密码哈希攻击（如彩虹表攻击和暴力破解）的抵抗力。
     *
     * @param str   需要加密的明文字符串
     * @return  加密后的字符串
     */
    String encryptByBCrypt(String str);

    /**
     * <!-- 校验BCrypt算法加密的字符串 -->
     * <p>
     * BCrypt算法是一种强大的密码哈希函数，由Niels Provos和David Mazières在1999年设计，
     * 旨在为基于密码的身份验证提供安全散列。它基于Blowfish加密算法的变体，
     * 并结合了几个关键的安全特性来增强对密码哈希攻击（如彩虹表攻击和暴力破解）的抵抗力。
     *
     * @param str   明文字符串
     * @param encodeStr 密文字符串（数据库中存储的字符串）
     * @return  true：匹配，false：不匹配
     */
    Boolean matchByBCrypt(String str, String encodeStr);

    /**
     * <!-- 生成随机AES密钥 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param bit   根据你的安全需求，你也可以选择生成128或192或256位的密钥
     * @return  随机AES密钥
     */
    SecretKey generateAESKey(int bit) throws NoSuchAlgorithmException;

    /**
     * <!-- 将byte[]转换成SecretKey -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param keyMaterial 密钥的byte[]
     * @return  AES密钥
     */
    SecretKey convertAESKey(byte[] keyMaterial) ;

    /**
     * <!-- 使用AES算法对字符串加密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param keyValue  AES密钥
     * @param str       要加密的字符串
     * @return  加密后的数据
     */
    byte[] encryptByAES(SecretKey keyValue, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException;

    /**
     * <!-- 使用AES算法对字符串加密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param str       要加密的字符串
     * @return  加密后的数据
     */
    byte[] encryptByAES(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException;

    /**
     * <!-- 使用AES算法对字符串解密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param keyValue AES密钥
     * @param bytes    加密后的字符串
     * @return  解密后的字符串
     */
    String decryptByAES(SecretKey keyValue, byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException;

    /**
     * <!-- 使用AES算法对字符串解密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param bytes    加密后的字符串
     * @return  解密后的字符串
     */
    String decryptByAES(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException;

    /**
     * <!-- 生成RSA公钥和私钥 -->
     *
     * <p>
     * RSA加密是一种公钥密码体制，它是目前应用最广泛的非对称加密算法之一。非对称加密意味着加密和解密使用两个不同的密钥，这两个密钥在数学上相关联，
     * 但不能从一个密钥直接推导出另一个密钥。
     *
     * @param keySize   密钥位数
     * @return  公钥及私钥
     */
    RSASecretKey generateRSAKey(Integer keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;

    /**
     * <!-- 使用RSA公钥加密字符串 -->
     *
     * @param publicKey 公钥
     * @param str   要加密的字符串
     * @return  加密后的字符串
     */
    byte[] encryptByRSA(PublicKey publicKey, String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * <!-- 使用RSA公钥加密字符串 -->
     * <p>
     *     不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param str   要加密的字符串
     * @return  加密后的字符串
     */
    byte[] encryptByRSA(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException;

    /**
     * <!-- 使用RSA私钥解密 -->
     *
     * @param privateKey    私钥
     * @param encryptedBytes  要解密的数据
     * @return  解密后的字符串
     */
    String decryptByRSA(PrivateKey privateKey, byte[] encryptedBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

    /**
     * <!-- 使用RSA私钥解密 -->
     * <p>
     *     不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param encryptedBytes  要解密的数据
     * @return  解密后的字符串
     */
    String decryptByRSA(byte[] encryptedBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException;



}
