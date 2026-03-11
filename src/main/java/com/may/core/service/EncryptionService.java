package com.may.core.service;

/**
 * 加解密服務接口
 * 支持 BCrypt、AES、RSA、ECC、SM2、SM3、SM4、SHA、MD5 等多種算法
 */
public interface EncryptionService {

    // ==================== BCrypt 密碼哈希 ====================

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

    // ==================== AES 對稱加密 ====================

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

    // ==================== SM4 對稱加密（國密） ====================

    /**
     * <!-- 使用SM4算法对字符串加密 -->
     * <p>
     * SM4是中国国家密码管理局发布的分组密码标准，用于无线局域网产品。
     * SM4是一种对称加密算法，密钥长度和分组长度均为128位。
     * 
     * @param keyValue SM4密钥
     * @param str      要加密的字符串
     * @return 加密后的数据（Base64编码）
     */
    String encryptBySM4(String keyValue, String str);

    /**
     * <!-- 使用SM4算法对字符串加密 -->
     * <p>
     * SM4是中国国家密码管理局发布的分组密码标准，用于无线局域网产品。
     * SM4是一种对称加密算法，密钥长度和分组长度均为128位。
     * 使用配置文件中指定的SM4密钥进行加密。
     *
     * @param str 要加密的字符串
     * @return 加密后的数据（Base64编码）
     */
    String encryptBySM4(String str);

    /**
     * <!-- 使用SM4算法对字符串解密 -->
     * <p>
     * SM4是中国国家密码管理局发布的分组密码标准，用于无线局域网产品。
     * SM4是一种对称加密算法，密钥长度和分组长度均为128位。
     *
     * @param keyValue SM4密钥
     * @param str      加密后的字符串（Base64编码）
     * @return 解密后的字符串
     */
    String decryptBySM4(String keyValue, String str);

    /**
     * <!-- 使用SM4算法对字符串解密 -->
     * <p>
     * SM4是中国国家密码管理局发布的分组密码标准，用于无线局域网产品。
     * SM4是一种对称加密算法，密钥长度和分组长度均为128位。
     * 使用配置文件中指定的SM4密钥进行解密。
     *
     * @param str 加密后的字符串（Base64编码）
     * @return 解密后的字符串
     */
    String decryptBySM4(String str);

    // ==================== RSA 非對稱加密 ====================

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

    // ==================== ECC 橢圓曲線加密 ====================

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

    // ==================== SM2 國密非對稱加密 ====================

    /**
     * <!-- 使用SM2公钥加密字符串 -->
     * <p>
     * SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法。
     * 基于椭圆曲线离散对数问题，具有比RSA更高的安全性和更短的密钥。
     * </p>
     *
     * @param publicKey SM2公钥
     * @param str       要加密的字符串
     * @return 加密后的字符串（Base64编码）
     */
    String encryptBySM2(String publicKey, String str);

    /**
     * <!-- 使用SM2公钥加密字符串 -->
     * <p>
     * 使用配置文件中指定的SM2公钥进行加密。
     * SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法。
     * </p>
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串（Base64编码）
     */
    String encryptBySM2(String str);

    /**
     * <!-- 使用SM2私钥解密 -->
     * <p>
     * SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法。
     * 基于椭圆曲线离散对数问题，具有比RSA更高的安全性和更短的密钥。
     * </p>
     *
     * @param privateKey   SM2私钥
     * @param encryptedStr 要解密的数据（Base64编码）
     * @return 解密后的字符串
     */
    String decryptBySM2(String privateKey, String encryptedStr);

    /**
     * <!-- 使用SM2私钥解密 -->
     * <p>
     * 使用配置文件中指定的SM2私钥进行解密。
     * SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法。
     * </p>
     *
     * @param encryptedStr 要解密的数据（Base64编码）
     * @return 解密后的字符串
     */
    String decryptBySM2(String encryptedStr);

    // ==================== SHA 消息摘要 ====================

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
     * @param str          要校验的数据
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
     * @param str          要校验的数据
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
     * @param str          要校验的数据
     * @return 校验结果
     */
    Boolean verifySHA512(String encryptedStr, String str);

    // ==================== SM3 消息摘要（國密） ====================

    /**
     * <!-- 使用SM3加密 -->
     * <p>
     * SM3是中国国家密码管理局发布的密码杂凑算法，输出长度为256位。
     * 适用于数字签名、消息认证码、随机数生成等场景。
     * </p>
     *
     * @param str 要加密的字符串
     * @return 加密后的字符串（Hex编码）
     */
    String encryptSM3(String str);

    /**
     * <!-- 校验SM3加密的字符 -->
     * <p>
     * SM3是中国国家密码管理局发布的密码杂凑算法，输出长度为256位。
     * </p>
     *
     * @param encryptedStr 加密后的数据（Hex编码）
     * @param str          要校验的数据
     * @return 校验结果
     */
    Boolean verifySM3(String encryptedStr, String str);

    // ==================== MD5 消息摘要 ====================

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
     * @param str          要校验的数据
     * @return 校验结果
     */
    Boolean verifyMD5(String encryptedStr, String str);

    // ==================== 統一哈希接口（支持鹽值） ====================

    /**
     * <!-- 使用指定算法和盐值进行哈希加密 -->
     * <p>
     * 统一的哈希接口，支持多种算法和自定义盐值。
     * 适用于需要更高灵活性的场景。
     * </p>
     *
     * @param algorithm 哈希算法（MD5、SHA-1、SHA-256、SHA-512、SM3）
     * @param str       要加密的字符串
     * @param salt      盐值（可选，为null时不使用盐值）
     * @return 加密后的字符串
     */
    String hash(String algorithm, String str, String salt);

    /**
     * <!-- 校验统一哈希接口加密的字符 -->
     *
     * @param algorithm    哈希算法
     * @param encryptedStr 加密后的数据
     * @param str          要校验的数据
     * @param salt         盐值
     * @return 校验结果
     */
    Boolean verifyHash(String algorithm, String encryptedStr, String str, String salt);

}