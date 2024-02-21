package com.may.core.service;

public interface EncryptionService {

    /**
     * <!-- 使用BCrypt算法加密字符串 -->
     * <p>
     * BCrypt算法是一种强大的密码哈希函数，由Niels Provos和David Mazières在1999年设计，
     * 旨在为基于密码的身份验证提供安全散列。它基于Blowfish加密算法的变体，
     * 并结合了几个关键的安全特性来增强对密码哈希攻击（如彩虹表攻击和暴力破解）的抵抗力。
     *
     * @param str 需要加密的明文字符串
     * @return 加密后的字符串
     */
    String encryptByBCrypt(String str);

    /**
     * <!-- 校验BCrypt算法加密的字符串 -->
     * <p>
     * BCrypt算法是一种强大的密码哈希函数，由Niels Provos和David Mazières在1999年设计，
     * 旨在为基于密码的身份验证提供安全散列。它基于Blowfish加密算法的变体，
     * 并结合了几个关键的安全特性来增强对密码哈希攻击（如彩虹表攻击和暴力破解）的抵抗力。
     *
     * @param str       明文字符串
     * @param encodeStr 密文字符串（数据库中存储的字符串）
     * @return true：匹配，false：不匹配
     */
    Boolean matchByBCrypt(String str, String encodeStr);

    /**
     * <!-- 使用AES算法对字符串加密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param keyValue AES密钥
     * @param str      要加密的字符串
     * @return 加密后的数据
     */
    String encryptByAES(String keyValue, String str);

    /**
     * <!-- 使用AES算法对字符串加密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param str 要加密的字符串
     * @return 加密后的数据
     */
    String encryptByAES(String str);

    /**
     * <!-- 使用AES算法对字符串解密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param keyValue AES密钥
     * @param str      加密后的字符串
     * @return 解密后的字符串
     */
    String decryptByAES(String keyValue, String str);

    /**
     * <!-- 使用AES算法对字符串解密 -->
     * <p>
     * AES（Advanced Encryption Standard）算法是一种广泛采用的对称密钥加密标准，由美国国家标准与技术研究院（NIST）于2001年正式发布，
     * 作为DES加密算法的替代方案。AES设计者是比利时密码学家Joan Daemen和Vincent Rijmen，其基础算法被称为Rijndael。
     *
     * @param str 加密后的字符串
     * @return 解密后的字符串
     */
    String decryptByAES(String str);

    /**
     * <!-- 使用RSA公钥加密字符串 -->
     *
     * @param publicKey 公钥
     * @param str       要加密的字符串
     * @return 加密后的字符串
     */
    String encryptByRSA(String publicKey, String str);

    /**
     * <!-- 使用RSA公钥加密字符串 -->
     * <p>
     * 不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    String encryptByRSA(String str);

    /**
     * <!-- 使用RSA私钥解密 -->
     *
     * @param privateKey   私钥
     * @param encryptedStr 要解密的数据
     * @return 解密后的字符串
     */
    String decryptByRSA(String privateKey, String encryptedStr);

    /**
     * <!-- 使用RSA私钥解密 -->
     * <p>
     * 不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param encryptedStr 要解密的数据
     * @return 解密后的字符串
     */
    String decryptByRSA(String encryptedStr);

    /**
     * <!-- 使用ECC公钥加密字符串 -->
     * <p>
     * 不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    String encryptByECC(String str);

    /**
     * <!-- 使用ECC公钥加密字符串 -->
     *
     * @param publicKey 公钥
     * @param str       要加密的字符串
     * @return 加密后的字符串
     */
    String encryptByECC(String publicKey, String str);

    /**
     * <!-- 使用ECC私钥解密 -->
     * <p>
     * 不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param encryptedStr 要解密的数据
     * @return 解密后的字符串
     */
    String decryptByECC(String encryptedStr);

    /**
     * <!-- 使用ECC私钥解密 -->
     * <p>
     * 不推荐将公钥/私钥保存在配置文件中
     * </p>
     *
     * @param encryptedStr 要解密的数据
     * @return 解密后的字符串
     */
    String decryptByECC(String privateKey, String encryptedStr);

    /**
     * <!-- 使用SHA-1加密 -->
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    String encryptSHA1(String str);

    /**
     * <!-- 校验SHA-1加密的字符 -->
     *
     * @param encryptedStr 加密后的数据
     * @param str 要校验的数据
     * @return 校验结果
     */
    Boolean verifySHA1(String encryptedStr, String str);

    /**
     * <!-- 使用SHA-256加密 -->
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    String encryptSHA256(String str);

    /**
     * <!-- 校验SHA-256加密的字符 -->
     *
     * @param encryptedStr 加密后的数据
     * @param str 要校验的数据
     * @return 校验结果
     */
    Boolean verifySHA256(String encryptedStr, String str);

    /**
     * <!-- 使用SHA-512加密 -->
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    String encryptSHA512(String str);

    /**
     * <!-- 校验SHA-512加密的字符 -->
     *
     * @param encryptedStr 加密后的数据
     * @param str 要校验的数据
     * @return 校验结果
     */
    Boolean verifySHA512(String encryptedStr, String str);

    /**
     * <!-- 使用MD5加密 -->
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串
     */
    String encryptMD5(String str);

    /**
     * <!-- 校验MD5加密的字符 -->
     *
     * @param encryptedStr 加密后的数据
     * @param str 要校验的数据
     * @return 校验结果
     */
    Boolean verifyMD5(String encryptedStr, String str);
}
